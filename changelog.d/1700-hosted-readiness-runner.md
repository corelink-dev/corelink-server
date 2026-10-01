Align the staging readiness contract with the existing GitHub-hosted Ubuntu
24.04 readiness, load and endurance jobs. The target guard now rejects runner
drift in each job; actual authenticated readiness remains required.
Credentialless Custom Domain PR checks use a separate queue per PR while all
protected staging provider operations retain their shared lock.
