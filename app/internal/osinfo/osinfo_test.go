package osinfo

import (
	"context"
	"testing"

	"app/internal/remote"
)

// patient01（Ubuntu 20.04）を想定した /etc/os-release。
// 実機で取った出力に差し替えると、より確かなテストになる。
const ubuntu2004 = `NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
`

const debian12 = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
`

func TestParseUbuntu(t *testing.T) {
	got := Parse(ubuntu2004)
	want := Info{ID: "ubuntu", Name: "Ubuntu", VersionID: "20.04", PrettyName: "Ubuntu 20.04.6 LTS"}
	if got != want {
		t.Fatalf("Parse() = %+v, want %+v", got, want)
	}
	if !got.Supported() {
		t.Fatal("Ubuntu は対応OSのはず")
	}
}

func TestParseDebianIsNotSupported(t *testing.T) {
	got := Parse(debian12)
	if got.ID != "debian" {
		t.Fatalf("ID = %q, want debian", got.ID)
	}
	if got.Supported() {
		t.Fatal("Debian は対応外のはず")
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	got := Parse("# comment\n\nID='ubuntu'\nbroken line\n")
	if got.ID != "ubuntu" {
		t.Fatalf("ID = %q, want ubuntu", got.ID)
	}
}

func TestDetect(t *testing.T) {
	r := &remote.FakeRunner{Outputs: map[string]string{"cat /etc/os-release": ubuntu2004}}
	info, err := Detect(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if info.VersionID != "20.04" {
		t.Fatalf("VersionID = %q", info.VersionID)
	}
}

func TestDetectEmpty(t *testing.T) {
	r := &remote.FakeRunner{Outputs: map[string]string{"cat /etc/os-release": ""}}
	if _, err := Detect(context.Background(), r); err == nil {
		t.Fatal("空の出力はエラーになるはず")
	}
}
