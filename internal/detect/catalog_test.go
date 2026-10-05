package detect_test

import (
	"reflect"
	"testing"
	"testing/fstest"

	"webscan/internal/detect"
)

func TestTechnologyMetadata(t *testing.T) {
	engine, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(document(
		technology("z-parent", validRule, `"a-inferred"`) + "," + technology("a-inferred", "", "")))}})
	if err != nil {
		t.Fatal(err)
	}
	want := []detect.TechnologyInfo{
		{ID: "a-inferred", Name: "Example", Category: detect.Framework},
		{ID: "z-parent", Name: "Example", Category: detect.Framework},
	}
	got := engine.Technologies()
	if !reflect.DeepEqual(got, want) || len(got) != engine.Len() {
		t.Fatalf("metadata=%+v, want %+v", got, want)
	}
	got[0].Name = "changed"
	if !reflect.DeepEqual(engine.Technologies(), want) {
		t.Fatal("returned metadata must not mutate the engine")
	}
	empty, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(document(""))}})
	if err != nil {
		t.Fatal(err)
	}
	if items := empty.Technologies(); items == nil || len(items) != 0 {
		t.Fatalf("want non-nil empty metadata, got %+v", items)
	}
}
