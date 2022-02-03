package policies

import future.keywords.in

foobar = true

foo_bar = true

allow_commit {
	input.request.pathParams.projectId == "5df2260277baff0011fde823"
}

filter_projects {
	resource := data.resources[_]
	bindings := input.user.bindings[_]
	roles := input.user.roles[_]
	roles.roleId == bindings.roles[_]
	roles.permissions[_] == "console.project.view"
	bindings.resource.resourceType == "custom"
	resource._id == bindings.resource.resourceId
}

filter_projects {
	resource := data.resources[_]
	bindings := input.user.bindings[_]
	bindings.resource.resourceType == "custom"
	bindings.permissions[_] == "console.project.view"
	resource._id == bindings.resource.resourceId
}

projection_feature_toggle[res] {
	ft_not_allowed := {x | 
		some key, val in input.response.body
			ft_checker with input.ft as key
		x = key
	}
	res := object.remove(input.response.body, ft_not_allowed)
}

ft_checker {
	ft := input.ft
	ft == "TEST_FT_1"
	true
}

allow_with_find_one {
	project := find_one("projects", {"projectId": "some-project"})
	true
	project.tenantId == "some-tenant"
}

allow_with_find_many {
	projects := find_many("projects", {"$or": [{"projectId": "some-project"}, {"projectId": "some-project2"}]})
	count(projects) == 2

	projects[0].tenantId == "some-tenant"
	projects[1].tenantId == "some-tenant2"
}
