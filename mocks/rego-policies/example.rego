package policies

foobar = true

foo_bar = true

default filter_projects = false

filter_projects {
	resource := data.resources[_]
	bindings := input.user.bindings[_]
	roles := input.user.roles[_]
	roles.roleId == bindings.roles[_]
	roles.permissions[_] == "console.project.view"
	bindings.resource.resourceType == "project"
	resource._id == bindings.resource.resourceId
}

filter_projects {
	resource := data.resources[_]
	bindings := input.user.bindings[_]
	bindings.resource.resourceType == "project"
	bindings.permissions[_] == "console.project.view"
	resource._id == bindings.resource.resourceId
}
