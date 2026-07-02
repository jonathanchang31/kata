# GitHub Automation Boundary

Kata is the evaluation engine. GitHub-specific automation lives in
`kata-bot`.

## Repo Boundary

- public `kata`
  - engine, pack registry, lane state, kings, submissions
- `kata-bot`
  - webhook relay, durable PR queue, resident validator service
  - runs `kata submission inspect-pr / validate / evaluate / verify / decide`
  - merges winners, applies GitTensor labels, runs `kata king promote`

## Flow

1. GitHub webhook arrives for a PR on the kata repo.
2. The bot verifies the signature and enqueues a durable job.
3. The worker stages a PR worktree and runs the Kata CLI end to end.
4. The duel runs in the pinned Bitsec sandbox with repeated replicas.
5. The bot comments SN60 metrics (screening status, scores, codebases
   passed, true positives, invalid runs) and applies the final action:
   merge, close-losing, close-invalid, or rerun-stale.
6. After a merge, the bot commits and pushes the updated `kings/` artifact
   and `lanes/` state from a clean default-branch worktree.
