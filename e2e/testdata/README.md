A TEST master key pair, public on purpose: the end-to-end test and CI play the iPhone with it (they set up
their own throwaway secrets with it: a Recover from test stores). Nothing in production trusts it: production's
secrets takes its master key from Deyao's app (Reset), and the private half of that key exists only in his
recovery kit.
