package verify

import "testing"

func TestBypassed(t *testing.T) {
	uses := map[string]string{
		"httplib2": "/venv/lib/python3.12/site-packages/certifi/cacert.pem",
		"gcloud":   "/etc/ssl/certs/ca-certificates.crt",
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/local/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem", true},
		{"/usr/local/lib/python3.12/site-packages/httplib2/cacerts.txt", true},
		{"/usr/lib/google-cloud-sdk/platform/bq/third_party/certifi/cacert.pem", true},
		{"/usr/local/lib/python3.12/site-packages/grpc/_cython/_credentials/roots.pem", false},
		{"/usr/local/lib/python3.12/site-packages/botocore/cacert.pem", false}, // botocore did not report
		{"/venv/lib/python3.12/site-packages/certifi/cacert.pem", false},
	}
	for _, c := range cases {
		if got := bypassed(c.path, uses) != ""; got != c.want {
			t.Errorf("bypassed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	if bypassed("/x/site-packages/httplib2/cacerts.txt", map[string]string{"httplib2": "/x/site-packages/httplib2/cacerts.txt"}) != "" {
		t.Error("httplib2 that resolves to its own bundle must count")
	}
}
