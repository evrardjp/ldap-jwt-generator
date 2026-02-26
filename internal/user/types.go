package user

type Details struct {
	Name   string
	DN     string
	Email  string
	Groups []string // Store alls the user groups (search is based on implementation!), including the ProjectAccess groups
}
