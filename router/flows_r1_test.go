package main

import "testing"

// R1 audit: a harness (router policy) can't put the deploy-key token store into a session
func TestNoHarnessBringsTheDeployKeyToken(t *testing.T) {
	r := &Router{}
	if _, err := r.withHarnessStores([]string{"default"}, []string{"github-deploy-keys"}); err == nil {
		t.Fatal("github-deploy-keys went to a session")
	}
	if _, err := r.withHarnessStores([]string{"default"}, []string{"tunnel"}); err != nil {
		t.Fatal(err)
	}
}
