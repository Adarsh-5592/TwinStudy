# GitHub release steps

1. Extract this archive into a clean folder.
2. Review `git status` and confirm no `.env`, database, or user-data files exist.
3. Add the repository as `origin` if needed, then create a release branch.
4. Commit the release files and push the branch.
5. Open a pull request to `main`; inspect changed files and CI results before merging.
6. Configure production secrets and managed database through the hosting provider; never commit secrets.
