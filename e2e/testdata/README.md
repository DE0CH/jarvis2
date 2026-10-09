A TEST master key pair, public on purpose: the end-to-end test and CI play the iPhone's recovery with it.
Only the `jarvis2-session-test` image trusts it (session-image/Dockerfile, MASTER_PUB); the production image
and the production core trust only the real master key (keys/master.pub, k8s/apps/core.yaml), whose
private half is in Deyao's password manager.
