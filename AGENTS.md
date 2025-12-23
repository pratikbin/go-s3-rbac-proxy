---
alwaysApply: true
---

# Things to remember

- Don't focus on docs, docker, dockerfiles, k8s manifests, makefiles, examples unless explicitly asked
- Always target for performance for amd64 cause we'll be runnning it on non resrouce critical environment unleses explicitly asked
- At the end of all the `**.go` file changes, must run test cases if there any, then golangci-lint, staticcheck, gosec, govulncheck parallely as well if you want
- if testcases fails, check the code first, then change the testcase if requires
- If you are unsure how to do something, use `gh_grep` to search code examples from github.
- once plans completes delete plan file
- When you need to search docs, use `context7` tools; for long-term project memory, use `chroma` MCP.
- Save architectural decisions or specific project patterns to Chroma using `add_documents` in the `project_knowledge` collection.
- all the metrics should be non blocking with the core business logic as long as it's possible
