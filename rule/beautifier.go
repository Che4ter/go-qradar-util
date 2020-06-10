package rule

import (
	"strings"
)

func RenderConditionAsHTML(conditions []Conditions) string {
	resultHTML := ""
	for _, testDefinition := range conditions {
		htmlTestCondition := "and "
		if testDefinition.Negate {
			htmlTestCondition += "<b>NOT</b> "
		}

		htmlTestCondition += testDefinition.Condition
		for _, parameter := range testDefinition.Selections {
			htmlTestCondition = strings.Replace(htmlTestCondition, "{}", "<b>"+strings.ReplaceAll(parameter, ", ", "</b>, <b>")+"</b> ", 1)
		}
		resultHTML += htmlTestCondition + "<br/>"
	}
	return resultHTML
}

func RenderConditionAsText(conditions []Conditions) string {
	resultText := ""
	for _, testDefinition := range conditions {
		textTestCondition := "and "
		if testDefinition.Negate {
			textTestCondition += "NOT "
		}

		textTestCondition += testDefinition.Condition
		for _, parameter := range testDefinition.Selections {
			textTestCondition = strings.Replace(textTestCondition, "{}", parameter+" ", 1)
		}
		resultText += textTestCondition
	}
	return resultText
}
