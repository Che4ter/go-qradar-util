package rule

import (
	"container/list"
	"context"
	"encoding/xml"
	"fmt"
	"github.com/Che4ter/dag"
	"github.com/ilyaglow/go-qradar"
	"regexp"
	"strings"
	"time"
)

func NewClient(baseUrl string, securityToken string) (*QRadarClient, error) {
	apiClient, err := qradar.NewClient(
		baseUrl,
		qradar.SetSECKey(securityToken),
	)
	if err != nil {
		return nil, err
	}

	return &QRadarClient{
		api: apiClient,
	}, nil
}

func (client *QRadarClient) RetrieveParsedQRadarRules(filter string) (map[string]*ParsedRule, error) {
	rules, err := client.api.RuleWithData.Get(context.Background(), "", filter, 0, 0)
	if err != nil {
		return nil, err
	}

	buildingBlocks, err := client.api.BuildingBlockWithData.Get(context.Background(), filter, "", 0, 0)
	if err != nil {
		return nil, err
	}

	ruleByName := make(map[string]*ParsedRule)
	ruleByIdentifier := make(map[string]*ParsedRule)

	for _, rule := range rules {
		parsedRule, err := apiQRadarRuleToParsedRule(&rule)
		if err != nil {
			return nil, err
		}

		ruleByName[parsedRule.Name] = parsedRule
		ruleByIdentifier[parsedRule.Identifier] = parsedRule
	}

	for _, buildingBlock := range buildingBlocks {
		if _, hasKey := ruleByIdentifier[*buildingBlock.Identifier]; !hasKey {
			parsedRule := apiQRadarBuildingBlockToParsedRule(&buildingBlock)

			ruleByName[parsedRule.Name] = parsedRule
			ruleByIdentifier[parsedRule.Identifier] = parsedRule
		}
	}

	for _, rule := range ruleByIdentifier {
		rule.Conditions, _ = parseConditions(rule, ruleByIdentifier)
	}

	return ruleByName, nil
}

func (client *QRadarClient) RetrieveRuleByIdentifier(identifier string) (*ParsedRule, error) {
	rules, err := client.api.RuleWithData.Get(context.Background(), "", "", 0, 0)
	if err != nil {
		return nil, err
	}

	buildingBlocks, err := client.api.BuildingBlockWithData.Get(context.Background(), "", "", 0, 0)
	if err != nil {
		return nil, err
	}

	ruleByIdentifier := make(map[string]*ParsedRule)

	for _, rule := range rules {
		parsedRule, err := apiQRadarRuleToParsedRule(&rule)
		if err != nil {
			return nil, err
		}

		ruleByIdentifier[parsedRule.Identifier] = parsedRule
	}

	for _, buildingBlock := range buildingBlocks {
		if _, hasKey := ruleByIdentifier[*buildingBlock.Identifier]; !hasKey {
			parsedRule := apiQRadarBuildingBlockToParsedRule(&buildingBlock)

			ruleByIdentifier[parsedRule.Identifier] = parsedRule
		}
	}

	for _, rule := range ruleByIdentifier {
		if rule.Identifier == identifier {
			rule.Conditions, _ = parseConditions(rule, ruleByIdentifier)
			return rule, nil
		}

	}

	return nil, fmt.Errorf("rule with Identifier %s not found", identifier)
}

func (client *QRadarClient) GenerateRuleGraph(regexFilter string, filterIsInclusive bool) (*dag.DAG, error) {
	rules, err := client.RetrieveParsedQRadarRules("")
	if err != nil {
		return nil, err
	}

	contentGraph := dag.NewDAG()
	regex, _ := regexp.Compile(regexFilter)

	resolvedDependencies := make(map[string]*dag.Vertex)
	unresolvedDependencyQueue := list.New()
	for ruleName, rule := range rules {
		isRegexMatch := regex.MatchString(rule.Name)
		if !rule.IsBuildingBlock && (isRegexMatch && filterIsInclusive) || (!isRegexMatch && !filterIsInclusive) {
			if !contentGraph.VertexExists(ruleName) {
				newNode := dag.NewVertex(ruleName, rule)
				contentGraph.AddVertex(newNode)
				resolvedDependencies[ruleName] = newNode

				unresolvedDependencies := resolveRuleDependencies(contentGraph, newNode, rules)
				for _, dependencyName := range unresolvedDependencies {
					unresolvedDependencyQueue.PushBack(dependencyName)
				}
			}
		}
	}

	for unresolvedDependencyQueue.Len() > 0 {
		nextDependency := unresolvedDependencyQueue.Front()
		nextDependencyName := nextDependency.Value.(string)
		nodeToResolve, err := contentGraph.GetVertex(nextDependencyName)
		if err != nil {
			return nil, err
		}

		unresolvedDependencies := resolveRuleDependencies(contentGraph, nodeToResolve, rules)
		resolvedDependencies[nextDependencyName] = nodeToResolve
		unresolvedDependencyQueue.Remove(nextDependency)
		for _, dependencyName := range unresolvedDependencies {
			if _, ok := resolvedDependencies[nextDependencyName]; !ok {
				unresolvedDependencyQueue.PushBack(dependencyName)
			}
		}
	}
	return contentGraph, err
}

func UnmarshalRule(rule_xml string) (RuleXML, error) {
	ruleXML := RuleXML{}
	err := xml.Unmarshal([]byte(rule_xml), &ruleXML)
	return ruleXML, err
}

func apiQRadarRuleToParsedRule(apiRule *qradar.RuleWithData) (*ParsedRule, error) {
	ruleXML, err := UnmarshalRule(*apiRule.RuleXML)
	if err != nil {
		return &ParsedRule{}, err
	}

	parsedRule := ParsedRule{
		Id:               *apiRule.ID,
		Name:             *apiRule.Name,
		Identifier:       *apiRule.Identifier,
		CreationDate:     time.Unix(int64(*apiRule.CreationDate/1000), 0),
		ModificationDate: time.Unix(int64(*apiRule.ModificationDate/1000), 0),
		Enabled:          *apiRule.Enabled,
		Owner:            *apiRule.Owner,
		RuleXML:          *apiRule.RuleXML,
		IsBuildingBlock:  ruleXML.BuildingBlock,
	}
	return &parsedRule, nil
}

func apiQRadarBuildingBlockToParsedRule(apiRule *qradar.BuildingBlockWithData) *ParsedRule {
	parsedRule := ParsedRule{
		Id:               *apiRule.ID,
		Name:             *apiRule.Name,
		Identifier:       *apiRule.Identifier,
		CreationDate:     time.Unix(int64(*apiRule.CreationDate/1000), 0),
		ModificationDate: time.Unix(int64(*apiRule.ModificationDate/1000), 0),
		Enabled:          *apiRule.Enabled,
		Owner:            *apiRule.Owner,
		RuleXML:          *apiRule.RuleXML,
		IsBuildingBlock:  true,
	}
	return &parsedRule
}

func resolveRuleDependencies(contentGraph *dag.DAG, node *dag.Vertex, allRules map[string]*ParsedRule) []string {
	var newDependencies []string
	ruleToResolve := node.Value.(*ParsedRule)
	for _, condition := range ruleToResolve.Conditions {
		for _, dependencyName := range condition.Dependencies {
			childNode, err := contentGraph.GetVertex(dependencyName)
			if err != nil {
				if childRule, ok := allRules[dependencyName]; ok {
					childNode = dag.NewVertex(dependencyName, childRule)
					newDependencies = append(newDependencies, dependencyName)
					if err := contentGraph.AddVertex(childNode); err != nil {
						return nil
					}
				}
			}
			if err := contentGraph.AddEdge(node, childNode); err != nil {
				return nil
			}
		}
	}
	return newDependencies
}

func parseConditions(rule *ParsedRule, allRules map[string]*ParsedRule) ([]Conditions, error) {
	var testDefinitions []Conditions
	r, _ := regexp.Compile("<\\s*a[^>]*>(.*?)<\\s*/\\s*a>")

	ruleXML, err := UnmarshalRule(rule.RuleXML)
	if err != nil {
		return nil, err
	}

	for _, test := range ruleXML.TestDefinitions.Test {
		testDefinition := Conditions{}
		matches := r.FindAllStringSubmatch(test.Text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				testDefinition.Selections = append(testDefinition.Selections, match[1])
			}
		}
		testDefinition.Dependencies = []string{}
		for _, parameter := range test.Parameter {
			if parameter.Name == "getEventRules" && parameter.UserSelection != " " {
				identifiers := strings.Split(parameter.UserSelection, ", ")
				for _, identifier := range identifiers {
					if parsedRule, ok := allRules[identifier]; ok {
						testDefinition.Dependencies = append(testDefinition.Dependencies, parsedRule.Name)
					} else {
						return nil, fmt.Errorf("rule with identifier %s not found", identifier)
					}
				}
			}
		}
		testDefinition.Condition = r.ReplaceAllString(test.Text, "{}")

		testDefinition.Negate = test.Negate

		testDefinitions = append(testDefinitions, testDefinition)
	}

	return testDefinitions, nil
}

type QRadarClient struct {
	api *qradar.Client
}

type ParsedRule struct {
	Id               int
	Name             string
	Identifier       string
	CreationDate     time.Time
	ModificationDate time.Time
	Owner            string
	Enabled          bool
	Conditions       []Conditions
	RuleXML          string
	IsBuildingBlock  bool
}

type Conditions struct {
	Negate       bool
	Condition    string
	Selections   []string
	Dependencies []string
}

type RuleXML struct {
	XMLName         xml.Name        `xml:"rule"`
	Text            string          `xml:",chardata"`
	OverrideId      int             `xml:"overrideid,attr"`
	Owner           string          `xml:"owner,attr"`
	Scope           string          `xml:"scope,attr"`
	Type            string          `xml:"type,attr"`
	RoleDefinition  bool            `xml:"roleDefinition,attr"`
	BuildingBlock   bool            `xml:"buildingBlock,attr"`
	Enabled         bool            `xml:"enabled,attr"`
	ID              int             `xml:"id,attr"`
	Name            string          `xml:"name"`
	Notes           string          `xml:"notes"`
	TestDefinitions TestDefinitions `xml:"testDefinitions"`
	Actions         struct {
		Text                          string `xml:",chardata"`
		FlowAnalysisInterval          string `xml:"flowAnalysisInterval,attr"`
		IncludeAttackerEventsInterval string `xml:"includeAttackerEventsInterval,attr"`
		ForceOffenseCreation          string `xml:"forceOffenseCreation,attr"`
		OffenseMapping                string `xml:"offenseMapping,attr"`
	} `xml:"actions"`
	Responses struct {
		Text                     string `xml:",chardata"`
		ReferenceTableRemove     bool   `xml:"referenceTableRemove,attr"`
		ReferenceMapOfMapsRemove bool   `xml:"referenceMapOfMapsRemove,attr"`
		ReferenceMapOfSetsRemove bool   `xml:"referenceMapOfSetsRemove,attr"`
		ReferenceMapRemove       bool   `xml:"referenceMapRemove,attr"`
		ReferenceTable           bool   `xml:"referenceTable,attr"`
		ReferenceMapOfMaps       bool   `xml:"referenceMapOfMaps,attr"`
		ReferenceMapOfSets       bool   `xml:"referenceMapOfSets,attr"`
		ReferenceMap             bool   `xml:"referenceMap,attr"`
		Newevent                 struct {
			Text                  string `xml:",chardata"`
			LowLevelCategory      string `xml:"lowLevelCategory,attr"`
			OffenseMapping        string `xml:"offenseMapping,attr"`
			ForceOffenseCreation  bool   `xml:"forceOffenseCreation,attr"`
			Qid                   int    `xml:"qid,attr"`
			ContributeOffenseName bool   `xml:"contributeOffenseName,attr"`
			OverrideOffenseName   bool   `xml:"overrideOffenseName,attr"`
			DescribeOffense       bool   `xml:"describeOffense,attr"`
			Relevance             string `xml:"relevance,attr"`
			Credibility           string `xml:"credibility,attr"`
			Severity              string `xml:"severity,attr"`
			Description           string `xml:"description,attr"`
			Name                  string `xml:"name,attr"`
		} `xml:"newevent"`
	} `xml:"responses"`
}

type TestDefinitions struct {
	Text string     `xml:",text"`
	Test []RuleTest `xml:"test"`
}

type RuleTest struct {
	RequiredCapabilities string `xml:"requiredCapabilities,attr"`
	Group                string `xml:"group,attr"`
	Uid                  int    `xml:"uid,attr"`
	Name                 string `xml:"name,attr"`
	ID                   int    `xml:"id,attr"`
	GroupId              int    `xml:"groupId,attr"`
	Negate               bool   `xml:"negate,attr"`
	Text                 string `xml:"text"`
	Visable              bool   `xml:"visable,attr"`
	Parameter            []struct {
		Text           string `xml:",chardata"`
		ID             int    `xml:"id,attr"`
		InitialText    string `xml:"initialText"`
		SelectionLabel string `xml:"selectionLabel"`
		UserOptions    struct {
			Text        string `xml:",chardata"`
			Multiselect bool   `xml:"multiselect,attr"`
			Method      string `xml:"method,attr"`
			Source      string `xml:"source,attr"`
			Format      string `xml:"format,attr"`
			Errorkey    string `xml:"errorkey,attr"`
			Validation  string `xml:"validation,attr"`
			Ordered     bool   `xml:"ordered,attr"`
			Option      []struct {
				Text string `xml:",chardata"`
				ID   string `xml:"id,attr"`
			} `xml:"option"`
		} `xml:"userOptions"`
		UserSelection      string `xml:"userSelection"`
		UserSelectionTypes string `xml:"userSelectionTypes"`
		UserSelectionId    int    `xml:"userSelectionId"`
		Name               string `xml:"name"`
	} `xml:"parameter"`
}
