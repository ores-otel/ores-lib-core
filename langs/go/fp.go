package orescore

import (
	"sort"
	"strings"
)

// Small, dependency-free functional helpers used to build values instead of
// mutating them in place. Go's generics are narrower than Rust's, so the
// building blocks here are deliberately tiny: map/filter over slices, a
// byte-wise predicate over strings, and set/sorted-unique constructors that
// always return a new collection and never touch the input.
//
// Style rule for this package (see docs/FUNCTIONAL-STYLE.md):
// prefer `value := build(inputs)` over `var value T; fill(&value)`. Where a
// hot path deliberately mutates in place, mark it with a
// `HOT-PATH (imperative by design)` comment explaining the allocation cost.

// mapSlice returns a new slice holding f(item) for every item of in.
func mapSlice[In, Out any](in []In, f func(In) Out) []Out {
	if in == nil {
		return nil
	}
	out := make([]Out, 0, len(in))
	for _, item := range in {
		out = append(out, f(item))
	}
	return out
}

// filterSlice returns a new slice holding the items of in that keep accepts.
func filterSlice[T any](in []T, keep func(T) bool) []T {
	if in == nil {
		return nil
	}
	out := make([]T, 0, len(in))
	for _, item := range in {
		if keep(item) {
			out = append(out, item)
		}
	}
	return out
}

// allSlice reports whether keep accepts every item of in (true for an empty slice).
func allSlice[T any](in []T, keep func(T) bool) bool {
	for _, item := range in {
		if !keep(item) {
			return false
		}
	}
	return true
}

// allBytes reports whether keep accepts every byte of value. It inspects raw
// bytes, not runes, so multi-byte UTF-8 sequences are visible to the predicate.
func allBytes(value string, keep func(byte) bool) bool {
	for index := 0; index < len(value); index++ {
		if !keep(value[index]) {
			return false
		}
	}
	return true
}

// keepRunes returns a new string holding only the runes of value that keep accepts.
func keepRunes(value string, keep func(rune) bool) string {
	return strings.Map(func(character rune) rune {
		if keep(character) {
			return character
		}
		return -1
	}, value)
}

// mapValues returns a new map with every key of in and f(key, value) as its value.
func mapValues[K comparable, V, Out any](in map[K]V, f func(K, V) Out) map[K]Out {
	out := make(map[K]Out, len(in))
	for key, value := range in {
		out[key] = f(key, value)
	}
	return out
}

// setOf builds a fresh membership set from ids. A nil input yields a nil set so
// callers can keep "no restriction requested" distinct from "nothing requested".
func setOf[T comparable](ids []T) map[T]struct{} {
	if ids == nil {
		return nil
	}
	out := make(map[T]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

// sortedUnique returns the sorted, de-duplicated form of ids as a new, non-nil
// slice; the input is never reordered.
func sortedUnique(ids []string) []string {
	distinct := setOf(ids)
	out := make([]string, 0, len(distinct))
	for id := range distinct {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
