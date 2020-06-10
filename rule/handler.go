package rule

import (
	"context"
	"encoding/xml"
	"errors"
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

func (client *QRadarClient) RetrieveQRadarRules(filter string) ([]ParsedRule, error) {
	var result []ParsedRule

	qradarRules, err := client.api.RuleWithData.Get(context.Background(), "", filter, 0, 0)

	for _, qradarRule := range qradarRules {
		ruleXML, err := UnmarshalRule(*qradarRule.RuleXML)
		if err != nil {
			return nil, err
		}

		if !ruleXML.BuildingBlock {
			parsedRule := ParsedRule{
				Id:               *qradarRule.ID,
				Name:             *qradarRule.Name,
				Identifier:       *qradarRule.Identifier,
				CreationDate:     time.Unix(int64(*qradarRule.CreationDate/1000), 0),
				ModificationDate: time.Unix(int64(*qradarRule.ModificationDate/1000), 0),
				Enabled:          *qradarRule.Enabled,
				Owner:            *qradarRule.Owner,
				RuleXML:          *qradarRule.RuleXML,
			}

			condition, err := ParseConditions(ruleXML)
			if err != nil {
				return nil, err
			}

			parsedRule.Conditions = condition

			result = append(result, parsedRule)
		}
	}

	return result, err
}

func (client *QRadarClient) RetrieveBuildingBlock(identifier string) (ParsedBuildingBlock, error) {
	filter := "identifier=\"" + identifier + "\""

	qradarBuildingBlock, err := client.api.BuildingBlockWithData.Get(context.Background(), "", filter, 0, 0)
	if err != nil{
		return ParsedBuildingBlock{}, err
	}
	if len(qradarBuildingBlock) == 1 {
		parsedBb := ParsedBuildingBlock{
			Id:               *qradarBuildingBlock[0].ID,
			Name:             *qradarBuildingBlock[0].Name,
			Identifier:       *qradarBuildingBlock[0].Identifier,
			CreationDate:     time.Unix(int64(*qradarBuildingBlock[0].CreationDate/1000), 0),
			ModificationDate: time.Unix(int64(*qradarBuildingBlock[0].ModificationDate/1000), 0),
			Owner:            *qradarBuildingBlock[0].Owner,
			Enabled:          *qradarBuildingBlock[0].Enabled,
			RuleXML:          *qradarBuildingBlock[0].RuleXML,
		}
		ruleXML, err := UnmarshalRule(*qradarBuildingBlock[0].RuleXML)
		if err != nil {
			return ParsedBuildingBlock{}, err
		}

		condition, err := ParseConditions(ruleXML)
		if err != nil {
			return ParsedBuildingBlock{}, err
		}

		parsedBb.Conditions = condition
		return parsedBb, nil
	}

	return ParsedBuildingBlock{}, errors.New("error: building block with identifier " + identifier + " not found. Maybe it's a rule?")
}

func UnmarshalRule(rule_xml string) (RuleXML, error) {
	ruleXML := RuleXML{}
	err := xml.Unmarshal([]byte(rule_xml), &ruleXML)
	return ruleXML, err
}

func ParseConditions(rule RuleXML) ([]Conditions, error) {
	var testDefinitions []Conditions
	r, _ := regexp.Compile("<\\s*a[^>]*>(.*?)<\\s*/\\s*a>")

	for _, test := range rule.TestDefinitions.Test {
		testDefinition := Conditions{}
		matches := r.FindAllStringSubmatch(test.Text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				testDefinition.Selections = append(testDefinition.Selections, match[1])
			}
		}

		for _, parameter := range test.Parameter {
			if parameter.Name == "getEventRules" && parameter.UserSelection != " " {
				testDefinition.BuildingBlockIdentifiers = strings.Split(parameter.UserSelection, ", ")
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
}

type ParsedBuildingBlock struct {
	Id               int
	Name             string
	Identifier       string
	CreationDate     time.Time
	ModificationDate time.Time
	Owner            string
	Enabled          bool
	Conditions       []Conditions
	RuleXML          string
}

type Conditions struct {
	Negate                   bool
	Condition                string
	Selections               []string
	BuildingBlockIdentifiers []string
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
