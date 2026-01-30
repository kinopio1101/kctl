package Print

import (
	"github.com/olekukonko/tablewriter"
	"os"
)

// Table is Struct for printable table
type Table struct {
	// Table Header as []string{"id","name","value" .....}
	Header []string
	// Table Body is content of table.
	Body [][]string
}

// Print function prints the table itself.
func (t *Table) Print(Caption string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(t.Header)
	table.SetAutoMergeCells(true)
	table.SetRowLine(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	var TableHeaderColor = make([]tablewriter.Colors, len(t.Header))
	for i := range TableHeaderColor {
		TableHeaderColor[i] = tablewriter.Colors{tablewriter.Bold, tablewriter.FgGreenColor}
	}
	table.SetHeaderColor(TableHeaderColor...)
	if Caption != "" {
		table.SetCaption(true, Caption)
	}
	table.AppendBulk(t.Body)
	table.Render()
}
