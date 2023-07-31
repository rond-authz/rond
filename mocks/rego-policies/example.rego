package policies

import future.keywords.in

foobar = true

todo = true

foo_bar = true

generate_filter {
	print(input)
	true
	query := data.resources[_]
	query.name == "jane"
}

responsepolicy [response] {
	response := {"msg": "hey there"}
}

original_path [response] {
	response := input.request.path
}

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


response_policy1 {
	true
}

response_policy2 {
	true
}

filter_req {
	filter := data.resources[_]
	filter.key == 42
}

testingPathParamsAbsence {
	object.get(input, ["request", "method"], false) == "GET"
	object.get(input, ["request", "pathParams"], false) == false
} {	
	object.get(input, ["request", "method"], false) == "PATCH"
	object.get(input, ["request", "pathParams"], false) != false
}

allow_view {
    id := object.get(input,["request","pathParams", "id"], false)
    id
}

assert_user {
	input.user.id == "the-user-id"
}