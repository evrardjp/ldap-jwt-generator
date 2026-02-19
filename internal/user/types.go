package user

type Details struct {
	Username string
	UserDN   string
	Email    string
	Groups   []string // Store alls the user groups (search is based on implementation!), including the ProjectAccess groups
}
