package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// tableColumn describes one column of an aligned list. right requests
// right-alignment, used for numeric columns (port, command counts, exit codes).
//
// The width fields drive the responsive layout (see fitColumns): a column starts
// at its natural content width clamped to [min,max], then weight decides its share
// of the squeeze (when the row is too wide) and of the slack (when there's room to
// spare). weight 0 is rigid — it holds its natural width unless squeezing it is
// the only way to fit. min 0 falls back to the header width so a header never
// truncates.
type tableColumn struct {
	header string
	right  bool
	min    int
	max    int
	weight int
}

// scrollWindow returns the [start,end) bounds of a vertical scroll window of the
// given visible height that keeps cursor in view. A height <= 0 or >= n shows all
// rows. It centralizes the windowing math shared by the Hosts, Sessions, and
// Discover lists.
func scrollWindow(cursor, n, height int) (start, end int) {
	if n == 0 {
		return 0, 0
	}
	if height <= 0 || height >= n {
		return 0, n
	}
	if cursor >= height {
		start = cursor - height + 1
	}
	end = start + height
	if end > n {
		end = n
	}
	return start, end
}

// colFit is the per-column flex spec consumed by fitColumns.
type colFit struct {
	min    int
	max    int // 0 == uncapped
	weight int // 0 == rigid
}

func clampCol(v, min, max int) int {
	// A misconfigured column (min above a positive max) keeps its min so the
	// header never truncates; min wins over an inverted cap.
	if max > 0 && max < min {
		max = min
	}
	if v < min {
		v = min
	}
	if max > 0 && v > max {
		v = max
	}
	return v
}

// fitColumns assigns each column a width so the row fills exactly `budget`
// content columns without exceeding it. Every column starts at its natural
// (content) width clamped to [min,max]; the surplus or deficit is then spread
// across columns by weight — growing toward max when there's slack, shrinking
// toward min when over budget. Rigid columns (weight 0) only move as a last
// resort (when even all-flexible-at-min still overflows). budget <= 0 means the
// caller doesn't know the width yet, so columns keep their clamped natural width.
func fitColumns(fits []colFit, natural []int, budget int) []int {
	w := make([]int, len(fits))
	total := 0
	for i := range fits {
		w[i] = clampCol(natural[i], fits[i].min, fits[i].max)
		total += w[i]
	}
	if budget <= 0 || total == budget {
		return w
	}
	if total < budget {
		growColumns(w, fits, budget-total)
	} else {
		deficit := shrinkColumns(w, fits, total-budget, true)
		shrinkColumns(w, fits, deficit, false)
	}
	return w
}

// growColumns hands `extra` content columns to weighted, not-yet-maxed columns
// in proportion to their weight, iterating so integer rounding and per-column
// caps settle without dropping or overshooting a column.
func growColumns(w []int, fits []colFit, extra int) {
	for extra > 0 {
		totalWeight := 0
		for i := range fits {
			if fits[i].weight > 0 && (fits[i].max == 0 || w[i] < fits[i].max) {
				totalWeight += fits[i].weight
			}
		}
		if totalWeight == 0 {
			return
		}
		moved := 0
		for i := range fits {
			if extra <= 0 {
				break
			}
			if fits[i].weight == 0 || (fits[i].max != 0 && w[i] >= fits[i].max) {
				continue
			}
			share := extra * fits[i].weight / totalWeight
			if share < 1 {
				share = 1
			}
			if share > extra {
				share = extra
			}
			if fits[i].max != 0 && w[i]+share > fits[i].max {
				share = fits[i].max - w[i]
			}
			if share <= 0 {
				continue
			}
			w[i] += share
			extra -= share
			moved += share
		}
		if moved == 0 {
			return
		}
	}
}

// shrinkColumns removes `deficit` columns from rows that have room above their
// min. flexibleOnly limits the pass to weighted columns; a second pass with
// flexibleOnly=false squeezes rigid columns too, so the row never overflows when
// the terminal is narrow. Returns any deficit it could not absorb (only nonzero
// when even all columns at their min still exceed the budget).
func shrinkColumns(w []int, fits []colFit, deficit int, flexibleOnly bool) int {
	for deficit > 0 {
		totalWeight := 0
		for i := range fits {
			if w[i] <= fits[i].min {
				continue
			}
			if flexibleOnly && fits[i].weight == 0 {
				continue
			}
			totalWeight += weightOr1(fits[i], flexibleOnly)
		}
		if totalWeight == 0 {
			return deficit
		}
		moved := 0
		for i := range fits {
			if deficit <= 0 {
				break
			}
			room := w[i] - fits[i].min
			if room <= 0 {
				continue
			}
			if flexibleOnly && fits[i].weight == 0 {
				continue
			}
			share := deficit * weightOr1(fits[i], flexibleOnly) / totalWeight
			if share < 1 {
				share = 1
			}
			if share > deficit {
				share = deficit
			}
			if share > room {
				share = room
			}
			if share <= 0 {
				continue
			}
			w[i] -= share
			deficit -= share
			moved += share
		}
		if moved == 0 {
			return deficit
		}
	}
	return deficit
}

func weightOr1(f colFit, flexibleOnly bool) int {
	if flexibleOnly {
		return f.weight
	}
	if f.weight > 0 {
		return f.weight
	}
	return 1
}

// fitCell truncates value to width and pads it back out to exactly width so its
// column renders at the target width (right columns pad on the left to keep the
// value flush-right). Padding every cell to its target is what lets the table
// fill the terminal width instead of collapsing to its natural size.
func fitCell(value string, width int, right bool) string {
	value = truncate(value, width)
	pad := width - lipgloss.Width(value)
	if pad <= 0 {
		return value
	}
	if right {
		return strings.Repeat(" ", pad) + value
	}
	return value + strings.Repeat(" ", pad)
}

// renderTable renders an aligned, borderless table from the given columns and
// the visible window of rows. cursor is the index (within rows) of the selected
// row, or -1 for a non-navigable list. avail is the terminal columns the table
// may occupy; columns are fitted to it (see fitColumns) so the row neither wraps
// at the default width nor leaves the rest of a wide terminal empty. A leading
// "▌" marker column keeps the selection visible even under NO_COLOR, where the
// background highlight is stripped (color is removed but glyphs are not).
//
// Callers pass an already-windowed slice of full (untruncated) rows; this helper
// fits, truncates, and aligns them. It replaces the flat strings.Join rendering
// across the Hosts, Discover, Policy, and Sessions tabs.
func renderTable(st appStyles, cols []tableColumn, rows [][]string, cursor, avail int) string {
	widths := tableWidths(cols, rows, avail)

	headers := make([]string, 0, len(cols)+1)
	headers = append(headers, "") // selection marker column
	for i, c := range cols {
		headers = append(headers, fitCell(c.header, widths[i], c.right))
	}

	data := make([][]string, len(rows))
	for i, r := range rows {
		marker := " "
		if i == cursor {
			marker = st.glyphs.Marker
		}
		cells := make([]string, 0, len(cols)+1)
		cells = append(cells, marker)
		for j := range cols {
			val := ""
			if j < len(r) {
				val = r[j]
			}
			cells = append(cells, fitCell(val, widths[j], cols[j].right))
		}
		data[i] = cells
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
			return s
		}).
		Headers(headers...).
		Rows(data...)
	return t.Render()
}

// tableWidths computes the per-column content widths for renderTable: the natural
// width of each column (header vs widest cell), fitted into the content budget
// that avail leaves after the marker column and the two-space cell padding.
func tableWidths(cols []tableColumn, rows [][]string, avail int) []int {
	natural := make([]int, len(cols))
	fits := make([]colFit, len(cols))
	for i, c := range cols {
		floor := c.min
		if floor <= 0 {
			floor = lipgloss.Width(c.header)
		}
		nat := lipgloss.Width(c.header)
		for _, r := range rows {
			if i < len(r) {
				if cw := lipgloss.Width(r[i]); cw > nat {
					nat = cw
				}
			}
		}
		natural[i] = nat
		fits[i] = colFit{min: floor, max: c.max, weight: c.weight}
	}
	// Budget = avail minus the marker column (1 content + 1 right pad) and the
	// left+right padding (2) every data column carries. Mirrors the measured
	// lipgloss/table overhead: total = 2 + Σ(width + 2).
	budget := avail - 2 - 2*len(cols)
	return fitColumns(fits, natural, budget)
}
