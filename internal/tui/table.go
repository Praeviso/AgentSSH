package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// tableColumn describes one column of an aligned list. right requests
// right-alignment, used for numeric columns (port, command counts, exit codes).
type tableColumn struct {
	header string
	right  bool
}

// renderTable renders an aligned, borderless table from the given columns and
// the visible window of rows. cursor is the index (within rows) of the selected
// row, or -1 for a non-navigable list. A leading "▌" marker column keeps the
// selection visible even under NO_COLOR, where the background highlight is
// stripped (color is removed but glyphs are not).
//
// Callers pass an already-windowed, already-truncated slice of rows; this helper
// only formats. It replaces the flat strings.Join rendering across the Hosts,
// Discover, Policy, and Sessions tabs.
func renderTable(st appStyles, cols []tableColumn, rows [][]string, cursor int) string {
	headers := make([]string, 0, len(cols)+1)
	headers = append(headers, "") // selection marker column
	for _, c := range cols {
		headers = append(headers, c.header)
	}

	data := make([][]string, len(rows))
	for i, r := range rows {
		marker := " "
		if i == cursor {
			marker = "▌"
		}
		data[i] = append([]string{marker}, r...)
	}

	t := table.New().
		Border(lipgloss.Border{}).
		BorderTop(false).BorderBottom(false).
		BorderLeft(false).BorderRight(false).
		BorderColumn(false).BorderRow(false).BorderHeader(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			var s lipgloss.Style
			switch {
			case row == table.HeaderRow:
				s = st.tableHeader
			case cursor >= 0 && row == cursor:
				s = st.tableSel
			default:
				s = st.tableCell
			}
			if col == 0 {
				// Tight marker column: no left padding, single-space gutter right.
				return s.Padding(0, 1, 0, 0)
			}
			if dc := col - 1; dc >= 0 && dc < len(cols) && cols[dc].right {
				return s.Align(lipgloss.Right)
			}
			return s
		}).
		Headers(headers...).
		Rows(data...)
	return t.Render()
}
