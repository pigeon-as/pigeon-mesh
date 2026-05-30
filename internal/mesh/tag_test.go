package mesh

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestParseTags_Empty(t *testing.T) {
	tags, err := ParseTags(nil)
	must.NoError(t, err)
	must.Nil(t, tags)
}

func TestParseTags_Happy(t *testing.T) {
	tags, err := ParseTags([]string{"role=control-plane", "region=west-europe"})
	must.NoError(t, err)
	must.MapEq(t, Tags{"role": "control-plane", "region": "west-europe"}, tags)
}

func TestParseTags_MissingEquals(t *testing.T) {
	_, err := ParseTags([]string{"role"})
	must.ErrorContains(t, err, "invalid tag")
}

func TestParseTags_EmptyKey(t *testing.T) {
	_, err := ParseTags([]string{"=value"})
	must.ErrorContains(t, err, "invalid tag")
}

func TestParseTags_EmptyValueAllowed(t *testing.T) {
	tags, err := ParseTags([]string{"role="})
	must.NoError(t, err)
	must.MapEq(t, Tags{"role": ""}, tags)
}
