package userimport

import (
	"testing"
)

func makeUsers(count int) []map[string]any {
	users := make([]map[string]any, count)
	for i := range users {
		users[i] = map[string]any{"username": "user"}
	}
	return users
}

func TestChunk_Empty(t *testing.T) {
	result := chunk(nil, 10)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d chunks", len(result))
	}
}

func TestChunk_EmptySlice(t *testing.T) {
	result := chunk([]map[string]any{}, 10)
	if len(result) != 0 {
		t.Errorf("expected empty result for empty slice, got %d chunks", len(result))
	}
}

func TestChunk_SingleUser(t *testing.T) {
	users := makeUsers(1)
	result := chunk(users, 10)
	if len(result) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(result))
	}
	if len(result[0]) != 1 {
		t.Errorf("expected chunk[0] length 1, got %d", len(result[0]))
	}
}

func TestChunk_ExactBatchSize(t *testing.T) {
	users := makeUsers(5)
	result := chunk(users, 5)
	if len(result) != 1 {
		t.Fatalf("expected 1 chunk for exact batch size, got %d", len(result))
	}
	if len(result[0]) != 5 {
		t.Errorf("expected chunk[0] length 5, got %d", len(result[0]))
	}
}

func TestChunk_BatchPlusOne(t *testing.T) {
	users := makeUsers(6)
	result := chunk(users, 5)
	if len(result) != 2 {
		t.Fatalf("expected 2 chunks for batch+1, got %d", len(result))
	}
	if len(result[0]) != 5 {
		t.Errorf("expected chunk[0] length 5, got %d", len(result[0]))
	}
	if len(result[1]) != 1 {
		t.Errorf("expected chunk[1] length 1, got %d", len(result[1]))
	}
}

func TestChunk_MultipleBatches(t *testing.T) {
	users := makeUsers(1000)
	result := chunk(users, 300)
	// 1000/300 = 3 full batches + 1 remainder
	if len(result) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(result))
	}
	total := 0
	for _, c := range result {
		total += len(c)
	}
	if total != 1000 {
		t.Errorf("total users across chunks = %d, expected 1000", total)
	}
}

func TestChunk_BatchSizeLargerThanInput(t *testing.T) {
	users := makeUsers(3)
	result := chunk(users, 100)
	if len(result) != 1 {
		t.Fatalf("expected 1 chunk when batch > input, got %d", len(result))
	}
	if len(result[0]) != 3 {
		t.Errorf("expected 3 users in chunk, got %d", len(result[0]))
	}
}
