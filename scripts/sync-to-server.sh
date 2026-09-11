#!/usr/bin/env bash
# 一键同步：本地提交 → 推送 fork → 推服务器临时分支 → 服务器预检 → 快进 → 哈希复核 → 清理
#
# 设计原则：先证明，再改动。
#   服务器上每个会覆写/移除文件的操作（stash、快进合并、丢 stash、删分支）之前，
#   都先用 git 自身的 blob 哈希证明“不会丢内容”；任何一项证明不通过就立刻中止，
#   并且中止前不改动服务器上的任何文件。
#   全程只用 git hash-object / rev-parse 比对内容，不依赖 md5sum。
#
# 为什么需要它：服务器 ~/flow2api 是 non-bare 仓库且 main 被 checkout，
# `git push server main` 会被 receive.denyCurrentBranch 拒绝；手工流程要
# 推临时分支 → 预检 → stash → ff → 复核 → 清理，漏一步就会留下半同步状态。
#
# 用法：
#   scripts/sync-to-server.sh                     # 工作区干净时，把 HEAD 同步到服务器
#   scripts/sync-to-server.sh -m "fix(x): ..."    # 先提交「已跟踪文件」的改动再同步
#   scripts/sync-to-server.sh -m "..." --add-untracked   # 提交时一并纳入未跟踪文件
#   scripts/sync-to-server.sh -n                  # dry-run：只打印计划，不推送不改动
#   scripts/sync-to-server.sh -r                  # 同步成功后重启服务器上的 headed 容器
#
# 退出码：0 成功（含已是最新）；1 中止（服务器未被改动，或按提示人工恢复）
set -euo pipefail

SERVER_REMOTE=server          # 服务器仓库的 git remote 名
SERVER_BRANCH=main            # 服务器上部署用的分支
FORK_REMOTE=myrepo            # fork 的 git remote 名（推送用）
FORK_BRANCH=main              # fork 上要更新的分支
MESSAGE=""                    # -m
ADD_UNTRACKED=0               # --add-untracked
DRY_RUN=0                     # -n
RESTART=0                     # -r
PUSH_FORK=1                   # --no-fork 关闭
FORCE_FORK=0                  # --force-fork：fork 分叉时用 force-with-lease
SERVER_URL_OVERRIDE=""        # --server-url：覆盖连接地址（也用于本地夹具自测）
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

usage() {
  cat <<'EOF'
用法：scripts/sync-to-server.sh [选项]

  -m, --message MSG     提交当前「已跟踪文件」的改动，提交说明为 MSG（不提供且工作区脏则中止）
      --add-untracked   提交时一并纳入未跟踪文件（默认不动未跟踪文件）
  -n, --dry-run         只打印计划，不推送、不改动服务器
  -r, --restart         同步成功后重启服务器上的 flow2api-headed 容器（会中断在途请求）
      --no-fork         跳过 fork 推送
      --force-fork      fork 已分叉时用 --force-with-lease 强推
      --fork NAME       fork 的 remote 名（默认 myrepo）
      --server-remote NAME  服务器 remote 名（默认 server）
      --server-branch NAME  服务器部署分支（默认 main）
      --server-url URL      覆盖服务器连接地址（user@host:path 或本地路径，后者用于自测）
  -h, --help            显示本帮助

流程：本地提交 → 推 fork → 推服务器临时分支 → 服务器预检（逐文件比对内容）
      → stash → 快进 → 还原额外文件 → 复核哈希 → 丢 stash → 删临时分支
EOF
}

die() { printf '\n✗ %s\n' "$*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }
info() { printf '  %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message)      MESSAGE="${2:-}"; shift 2 ;;
    --add-untracked)   ADD_UNTRACKED=1; shift ;;
    -n|--dry-run)      DRY_RUN=1; shift ;;
    -r|--restart)      RESTART=1; shift ;;
    --no-fork)         PUSH_FORK=0; shift ;;
    --force-fork)      FORCE_FORK=1; shift ;;
    --fork)            FORK_REMOTE="${2:-}"; shift 2 ;;
    --server-remote)   SERVER_REMOTE="${2:-}"; shift 2 ;;
    --server-branch)   SERVER_BRANCH="${2:-}"; shift 2 ;;
    --server-url)      SERVER_URL_OVERRIDE="${2:-}"; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "未知参数：$1（--help 查看用法）" ;;
  esac
done

cd "$(git rev-parse --show-toplevel)" || die "不在 git 仓库内"

# ---------------------------------------------------------------- 远程连接解析
# 支持三种形式：user@host:path（ssh）、ssh://user@host/path、/本地/路径（本地夹具自测）
RM_MODE=""; RM_HOST=""; RM_PATH=""
parse_remote_url() {
  local url="$1"
  case "$url" in
    ssh://*) RM_MODE=ssh; local rest="${url#ssh://}"
             RM_HOST="${rest%%/*}"; RM_PATH="/${rest#*/}" ;;
    /*|file://*) RM_MODE=local; RM_HOST=""; RM_PATH="${url#file://}" ;;
    *@*:*)   RM_MODE=ssh; RM_HOST="${url%%:*}"; RM_PATH="${url#*:}" ;;
    *:*)     RM_MODE=ssh; RM_HOST="${url%%:*}"; RM_PATH="${url#*:}" ;;
    *)       die "无法解析服务器地址：$url" ;;
  esac
}
SQ() { printf "'%s'" "${1//\'/\'\\\'\'}"; }

if [ -n "$SERVER_URL_OVERRIDE" ]; then
  SERVER_URL="$SERVER_URL_OVERRIDE"
  USING_REAL_REMOTE=0
else
  SERVER_URL="$(git remote get-url "$SERVER_REMOTE" 2>/dev/null)" || die "找不到 remote：$SERVER_REMOTE"
  USING_REAL_REMOTE=1
fi
parse_remote_url "$SERVER_URL"

# 远程执行：stdin 传入脚本，通过 env 传参（脚本内用 "${SYNC_DIR/#\~/$HOME}" 展开 ~）
# remote_run <目标提交> <临时分支 ref> <dry-run:0|1>
remote_run() {
  local new="$1" tmp="$2" dry="$3"
  if [ "$RM_MODE" = local ]; then
    env "SYNC_DIR=$RM_PATH" "SYNC_NEW=$new" "SYNC_TMP=$tmp" \
        "SYNC_DRY=$dry" "SYNC_BRANCH=$SERVER_BRANCH" bash -s
  else
    ssh "${SSH_OPTS[@]}" "$RM_HOST" \
      "env SYNC_DIR=$(SQ "$RM_PATH") SYNC_NEW=$(SQ "$new") SYNC_TMP=$(SQ "$tmp") SYNC_DRY=$(SQ "$dry") SYNC_BRANCH=$(SQ "$SERVER_BRANCH") bash -s"
  fi
}

# ---------------------------------------------------------------- 1. 本地提交
step "1/6 本地状态"
untracked_count=$(git ls-files -o --exclude-standard | wc -l | tr -d ' ')
if [ "$untracked_count" != 0 ]; then
  info "未跟踪文件 $untracked_count 个（默认不纳入提交，加 --add-untracked 可一并提交）"
fi
# 只把「已跟踪文件的未提交改动」视为阻塞：未跟踪文件不会进入提交，也不影响服务器
if [ -n "$(git status --porcelain -uno)" ]; then
  if [ -z "$MESSAGE" ]; then
    git status --short -uno
    die "已跟踪文件有未提交改动；用 -m \"提交说明\" 提交，或先自行处理"
  fi
  if [ "$ADD_UNTRACKED" = 1 ]; then
    git add -A
  else
    git add -u          # 只提交已跟踪文件的改动，避免把无关的新文件扫进来
  fi
  if [ -z "$(git diff --cached --name-only)" ]; then
    info "没有可提交的内容（未跟踪文件未纳入，可用 --add-untracked）"
  else
    git diff --cached --name-status | sed 's/^/  待提交: /'
    [ "$DRY_RUN" = 1 ] || git commit -q -m "$MESSAGE"
  fi
fi
NEW="$(git rev-parse HEAD)"
SHORT="${NEW:0:8}"
info "目标提交 $SHORT $(git log -1 --pretty=%s)"

# ---------------------------------------------------------------- 2. fork 推送
if [ "$PUSH_FORK" = 1 ]; then
  step "2/6 推送 fork（$FORK_REMOTE/$FORK_BRANCH）"
  if [ "$DRY_RUN" = 1 ]; then
    info "[dry-run] git push $FORK_REMOTE HEAD:$FORK_BRANCH"
  else
    git fetch -q "$FORK_REMOTE" || info "（fetch $FORK_REMOTE 失败，按本地记录判断）"
    if git rev-parse -q --verify "refs/remotes/$FORK_REMOTE/$FORK_BRANCH" >/dev/null \
       && [ "$(git rev-parse "refs/remotes/$FORK_REMOTE/$FORK_BRANCH")" = "$NEW" ]; then
      info "已是最新，跳过"
    elif [ "$FORCE_FORK" = 1 ]; then
      git push --force-with-lease "$FORK_REMOTE" "HEAD:refs/heads/$FORK_BRANCH"
    else
      git push "$FORK_REMOTE" "HEAD:refs/heads/$FORK_BRANCH" \
        || die "推送 fork 被拒（可能已分叉）；确认后加 --force-fork 重跑"
    fi
  fi
else
  step "2/6 推送 fork：已用 --no-fork 跳过"
fi

# ---------------------------------------------------------------- 3. 服务器预检（只读）
step "3/6 服务器预检（只读，不改动）"
if [ "$DRY_RUN" = 1 ]; then
  info "[dry-run] 跳过远程预检；真实执行时会逐文件比对内容后才动手"
  info "[dry-run] 远程地址：$SERVER_URL（$RM_MODE）"
fi

# ---------------------------------------------------------------- 4/5. 推临时分支 + 预检/快进/复核/清理
TMP_BRANCH="sync-$(date +%Y%m%d-%H%M%S)-$$"
TMP_REF="refs/heads/$TMP_BRANCH"

remote_phase() {
  cat <<'REMOTE'
set -euo pipefail
cd -- "${SYNC_DIR/#\~/$HOME}" || { echo "✗REMOTE 无法进入目录: $SYNC_DIR" >&2; exit 1; }
export GIT_TERMINAL_PROMPT=0
fail() { echo "✗REMOTE $*" >&2; exit 1; }
say()  { echo "  $*"; }

TMP_SHORT="${SYNC_TMP#refs/heads/}"   # git branch -d 只认短名
git rev-parse --verify -q "$SYNC_TMP^{commit}" >/dev/null || fail "临时分支不存在：$SYNC_TMP"
git rev-parse --verify -q "$SYNC_NEW^{commit}"  >/dev/null || fail "目标提交不存在：$SYNC_NEW"
ref=$(git symbolic-ref -q --short HEAD || true)
[ "$ref" = "$SYNC_BRANCH" ] || fail "服务器当前 checkout 的是 $ref，不是 $SYNC_BRANCH，拒绝操作"
CUR=$(git rev-parse HEAD)

NOOP=0
if [ "$CUR" = "$SYNC_NEW" ]; then
  NOOP=1
else
  git merge-base --is-ancestor "$CUR" "$SYNC_NEW" \
    || fail "非快进：服务器 $SYNC_BRANCH(${CUR:0:8}) 不是 ${SYNC_NEW:0:8} 的祖先，需人工合并"
fi
say "服务器当前 ${CUR:0:8} → 目标 ${SYNC_NEW:0:8}"

# 无需改动或 dry-run：在任何证明/改动之前退出。
# 注意必须写成显式 if——若写成 `cmd && { ...; exit; }`，一旦 cmd 失败，
# set -e 不生效，执行会穿透到改动阶段。
if [ "$SYNC_DRY" = 1 ]; then
  echo "DRYRUN_OK ${CUR:0:8}"; exit 0
fi
if [ "$NOOP" = 1 ]; then
  git branch -d "$TMP_SHORT" >/dev/null 2>&1 || true
  echo "ALREADY_SYNCED ${CUR:0:8}"; exit 0
fi

mapfile -d '' DIRTY < <(git ls-files -m -o --exclude-standard -z)
mapfile -d '' STAGED < <(git diff --name-only --cached -z)
mapfile -d '' CHANGED < <(git diff --name-only "$CUR" "$SYNC_NEW" -z)

in_list() { local needle="$1"; shift; local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1; }

# —— 证明阶段：不通过就退出，服务器一个字节都不动 ——
OVERLAP=(); EXTRA=(); EXTRA_HASH=()
# 服务器上脏文件分两类：
#   交集（本次改动也碰到它）→ 内容必须与目标 blob 完全一致，随后会被“收编”
#   其余 → stash 后必须原样还原（含未跟踪文件；被 .gitignore 忽略的文件不进 stash，天然安全）
for p in "${DIRTY[@]}" "${STAGED[@]}"; do
  [ -n "$p" ] || continue
  [ -e "$p" ] || fail "服务器上 $p 处于「工作区已删除」状态，无法证明不会丢内容，请先人工处理"
  have=$(git hash-object -- "$p")
  if in_list "$p" "${CHANGED[@]}"; then
    want=$(git rev-parse -q --verify "$SYNC_NEW:$p") || fail "目标提交会删除 $p，而它在服务器上有本地改动，拒绝覆写"
    [ "$have" = "$want" ] || fail "内容冲突：$p 服务器工作区 $have ≠ 目标 $want"
    OVERLAP+=("$p")
  else
    in_list "$p" "${EXTRA[@]}" && continue
    EXTRA+=("$p"); EXTRA_HASH+=("$have")
  fi
done

if [ ${#EXTRA[@]} -gt 0 ]; then
  say "stash 后需要原样还原的额外文件（本次改动不涉及）："
  for p in "${EXTRA[@]}"; do say "  - $p"; done
fi
if [ ${#OVERLAP[@]} -gt 0 ]; then
  say "与目标提交同名同内容、可直接收编的文件：${#OVERLAP[@]} 个"
fi
say "预检通过：不会丢内容"

# —— 改动阶段 ——
STASH_OID=""
if [ ${#DIRTY[@]} -gt 0 ] || [ ${#STAGED[@]} -gt 0 ]; then
  git stash push -u -q -m "pre-sync-${SYNC_NEW:0:8}" >/dev/null
  STASH_OID=$(git rev-parse refs/stash)
  say "已备份工作区到 stash ${STASH_OID:0:8}"
fi

git merge --ff-only -q "$SYNC_NEW" || {
  echo "✗REMOTE 快进合并失败；工作区备份仍在 stash ${STASH_OID:0:8}（git stash pop 可恢复），临时分支 $SYNC_TMP 未删" >&2
  exit 1
}
say "已快进到 ${SYNC_NEW:0:8}"

# 快进之后才出错的提示：main 已经动了，stash 是恢复入口
fail_after_merge() {
  echo "✗REMOTE $*" >&2
  echo "  服务器 $SYNC_BRANCH 已快进到 ${SYNC_NEW:0:8}；工作区备份保留在 stash ${STASH_OID:0:8}（git stash pop 可恢复），临时分支 $SYNC_TMP 未删" >&2
  exit 1
}

# 还原「本次改动不涉及」的文件（先查 stash 树=已跟踪，再查第三个父=未跟踪）
for i in "${!EXTRA[@]}"; do
  p="${EXTRA[$i]}"; want="${EXTRA_HASH[$i]}"; restored=0
  for tree in "$STASH_OID" "$STASH_OID^3"; do
    if git rev-parse -q --verify "$tree:$p" >/dev/null 2>&1; then
      mkdir -p -- "$(dirname -- "$p")"
      git show "$tree:$p" > "$p"; restored=1; break
    fi
  done
  [ "$restored" = 1 ] || fail_after_merge "无法从 stash 还原 $p"
  have=$(git hash-object -- "$p")
  [ "$have" = "$want" ] || fail_after_merge "$p 还原后内容不一致"
  echo "RESTORED $p"
done

# 复核收编文件
for p in "${OVERLAP[@]}"; do
  want=$(git rev-parse "$SYNC_NEW:$p")
  have=$(git hash-object -- "$p")
  [ "$have" = "$want" ] || fail_after_merge "合并后 $p 内容与目标不一致"
done

# 丢 stash 前的最后一道证明：stash 里的每个文件都必须已被「收编」或「还原」覆盖
if [ -n "$STASH_OID" ]; then
  mapfile -t stash_files < <(
    { git diff --name-only "$STASH_OID^" "$STASH_OID"
      git ls-tree -r --name-only "$STASH_OID^3" 2>/dev/null || true
    } | sort -u
  )
  unaccounted=()
  for p in "${stash_files[@]}"; do
    in_list "$p" "${OVERLAP[@]}" || in_list "$p" "${EXTRA[@]}" || unaccounted+=("$p")
  done
  if [ ${#unaccounted[@]} -gt 0 ]; then
    echo "✗REMOTE 以下文件在 stash 中但未被收编/还原，保留 stash ${STASH_OID:0:8} 不删：" >&2
    printf '    %s\n' "${unaccounted[@]}" >&2
    echo "  服务器 $SYNC_BRANCH 已快进到 ${SYNC_NEW:0:8}，临时分支 $SYNC_TMP 未删" >&2
    exit 1
  fi
  if git stash drop -q "$STASH_OID" 2>/dev/null; then
    :
  elif [ "$(git rev-parse refs/stash)" = "$STASH_OID" ]; then
    git stash drop -q
  else
    fail "无法按 oid 丢弃 stash，且 refs/stash 已不是它，保留 ${STASH_OID:0:8} 不删"
  fi
  say "已丢弃 stash ${STASH_OID:0:8}（内容全部落地，证明通过）"
fi

if git branch -d "$TMP_SHORT" >/dev/null 2>&1; then
  say "已删除临时分支 $TMP_SHORT"
else
  say "⚠ 临时分支 $TMP_SHORT 删除失败，同步本身已完成，可手动删除：git branch -D $TMP_SHORT"
fi
echo "SYNCED $(git rev-parse HEAD)"
REMOTE
}

step "4/6 推送临时分支 $TMP_REF"
if [ "$DRY_RUN" = 1 ]; then
  info "[dry-run] git push $SERVER_URL HEAD:$TMP_REF"
  info "[dry-run] 之后在服务器上执行预检 → stash → 快进 → 复核 → 清理"
else
  git push -q "$SERVER_URL" "HEAD:$TMP_REF" || die "推送临时分支失败（服务器未改动）"

  step "5/6 服务器预检 / 快进 / 复核 / 清理"
  set +e
  out=$(remote_phase | remote_run "$NEW" "$TMP_REF" 0)
  rc=$?
  set -e
  printf '%s\n' "$out"
  if [ $rc -ne 0 ]; then
    printf '\n清理临时分支 %s\n' "$TMP_REF"
    git push -q "$SERVER_URL" --delete "$TMP_REF" 2>/dev/null \
      && printf '  已删除\n' \
      || printf '  ⚠ 删除失败，请手动确认：git push %s --delete %s\n' "$SERVER_URL" "$TMP_REF"
    exit 1
  fi
fi

# ---------------------------------------------------------------- 6. 收尾校验
step "6/6 收尾校验"
if [ "$DRY_RUN" = 1 ]; then
  info "[dry-run] 未做任何改动"
  exit 0
fi
if [ "$USING_REAL_REMOTE" = 1 ]; then
  git fetch -q "$SERVER_REMOTE"
  remote_head="$(git rev-parse "$SERVER_REMOTE/$SERVER_BRANCH")"
  [ "$remote_head" = "$NEW" ] || die "校验失败：$SERVER_REMOTE/$SERVER_BRANCH 是 ${remote_head:0:8}，期望 ${NEW:0:8}"
  info "服务器 $SERVER_BRANCH 已等于 $SHORT"
else
  info "使用 --server-url 覆盖连接，跳过 remote-tracking 校验（服务器端已自校验）"
fi

if [ "$RESTART" = 1 ]; then
  step "附加：重启 headed 容器"
  info "会中断进行中的打码/流式生成，重启后首批打码变慢"
  cat <<'REMOTE' | remote_run "$NEW" "refs/heads/$TMP_BRANCH" 0
set -euo pipefail
cd -- "${SYNC_DIR/#\~/$HOME}" || exit 1
docker compose -f docker-compose.headed.yml -f docker-compose.headed-override.yml restart flow2api-headed
docker ps --format '{{.Names}}|{{.Status}}' | grep -E '^(flow2api-headed|grok2api)\|' || true
REMOTE
fi
printf '\n✓ 同步完成：本地 = fork = 服务器 %s\n' "$SHORT"
