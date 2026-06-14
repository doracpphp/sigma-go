package grammar

type Aggregation struct {
	Near             *Disjunction         `(  "near" @@`
	Function         *AggregationFunction `|  @@`
	AggregationField string               `   ("(" (@SearchIdentifier)? ")")?`
	GroupField       []string             `   ("by" @SearchIdentifier ("," @SearchIdentifier)*)?`
	Comparison       *ComparisonOp        `   (@@`
	Threshold        float64              `   @ComparisonValue)? )`
}

type AggregationFunction struct {
	Count bool `@"count"`
	Min   bool `| @"min"`
	Max   bool `| @"max"`
	Avg   bool `| @"avg"`
	Sum   bool `| @"sum"`
}

type ComparisonOp struct {
	Equal            bool `@"="`
	NotEqual         bool `| @"!="`
	LessThan         bool `| @"<"`
	LessThanEqual    bool `| @"<="`
	GreaterThan      bool `| @">"`
	GreaterThanEqual bool `| @">="`
}
