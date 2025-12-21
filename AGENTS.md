---
alwaysApply: true
---

# Things to remember

- Don't focus on docs, docker, dockerfiles, k8s manifests, makefiles, examples unless explicitly asked
- Always target for performance for amd64 cause we'll be runnning it on non resrouce critical environment unleses explicitly asked
- must run tests if there any then golangci-lint at the end of all the changes
- if testcases fails, check the code first, then change the testcase if requires
- once plans completes delete plan file
