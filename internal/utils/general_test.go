package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterList(t *testing.T) {
	input := []string{"a", "b", "a"}
	filter := []string{"a", "c"}
	out := FilterList(input, filter)
	require.Equal(t, []string{"b"}, out)
}

func TestSanitizeString(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{input: "test", expected: "test"},
		{input: "new\nline", expected: "newline"},
		{input: "carriage\rreturn", expected: "carriagereturn"},
		{input: "new\nline\ncarriage\rreturn\n\r", expected: "newlinecarriagereturn"},
	}

	for i, testCase := range testCases {
		t.Run(
			fmt.Sprintf("testcase #%d %s -> %s", i, testCase.input, testCase.expected),
			func(t *testing.T) {
				out := SanitizeString(testCase.input)
				require.Equal(t, testCase.expected, out)
			},
		)
	}
}

func TestReadFile(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		content, err := ReadFile("./testfile.txt")
		require.NoError(t, err)
		require.Equal(t, "the-content", string(content))
	})

	t.Run("ko", func(t *testing.T) {
		content, err := ReadFile("./missingfile.txt")
		require.Error(t, err)
		require.Nil(t, content)
	})
}
