package opatranslator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOPATranslator(t *testing.T) {
	t.Run("testing processTerm", func(t *testing.T) {
		query := "data.resources[_].manager"
		actual := processTerm(query)
		expected := []string{"resources", "manager"}
		require.Equal(t, expected, actual)
	})
}
