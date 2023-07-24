package policies

import future.keywords.in

allow_all {
  true
}

# filter_projects
#
# Used permissions:
#  - "console.project.view"
#  - "console.company.project.view"
#
filter_projects {
  resource := data.resources[_]
  bindings := input.user.bindings[_]
  filter_bindings_by_permission(bindings, "console.company.project.view")
  resource.tenantId == bindings.resource.resourceId
}{
  resource := data.resources[_]
  bindings := input.user.bindings[_]
  filter_bindings_by_permission(bindings, "console.project.view")
  resource._id == bindings.resource.resourceId
}

# allow_view_project
#
# Used permissions:
#  - "console.project.view"
#  - "console.company.project.view"
#
allow_view_project {
  user_has_permission_from_bindings("console.project.view", input.request.pathParams.id)
} {
  user_has_permission_from_bindings("console.project.view", input.request.pathParams.projectId)
} {
  not user_has_permission_from_bindings("console.project.view", input.request.pathParams.id)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.id }] }
  })
  user_has_permission_from_bindings("console.company.project.view", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.view", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId}] }
  })
  user_has_permission_from_bindings("console.company.project.view", project.tenantId)
}

# allow_create_project
#
# Used groups:
#  - "create_project"
#
allow_create_project {
  user_has_group("create_project")
}

# allow_commit
#
# Used permissions:
#  - "console.project.configuration.update"
#
allow_commit {
  user_has_permission_from_bindings("console.project.configuration.update", input.request.pathParams.projectId)
} {
  user_has_permission_from_bindings("console.project.configuration.update", input.request.query.projectId[0])
} {
  not user_has_permission_from_bindings("console.project.configuration.update", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.configuration.update", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.configuration.update", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.configuration.update", project.tenantId)
}

# allow_repository_creation
#
# Used permissions:
#   - console.project.service.repository.create
#

allow_service_repository_creation {
  user_has_permission_from_bindings("console.project.service.repository.create", input.request.pathParams.projectId)
}{
  user_has_permission_from_bindings("console.project.service.repository.create", input.request.query.projectId[0])
}{
  not user_has_permission_from_bindings("console.project.service.repository.create", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.service.repository.create", project.tenantId)
}{
  not user_has_permission_from_bindings("console.project.service.repository.create", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.service.repository.create", project.tenantId)
}

# allow_view_secret_envs_key
#
# Used permissions:
#   - console.project.view
#
allow_view_secret_envs_key {
  user_has_permission_from_bindings("console.project.view", input.request.pathParams.projectId)
} {
  user_has_permission_from_bindings("console.project.view", input.request.query.projectId[0])
}{
  not user_has_permission_from_bindings("console.project.view", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.view", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.view", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.view", project.tenantId)
}

# allow_manage_secret_envs
#
# Used permissions:
#   - console.project.secreted_variables.manage
#
allow_manage_secret_envs {
  user_has_permission_from_bindings("console.project.secreted_variables.manage", input.request.pathParams.projectId)
} {
  user_has_permission_from_bindings("console.project.secreted_variables.manage", input.request.query.projectId[0])
} {
  not user_has_permission_from_bindings("console.project.secreted_variables.manage", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.secreted_variables.manage", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.secreted_variables.manage", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.secreted_variables.manage", project.tenantId)
}

# projection_projects_list_environments
#
# Used permissions:
#   - console.project.view
#   - console.environment.view
#   - console.project.environment.view
#   - console.company.project.environment.view

projection_projects_list_environments [projects] {
    projects := [projects_with_envs_filtered |
        project := input.response.body[_]
        isAllowed := user_can_access_project_given_project(project)
        isAllowed
        allowed_envs := filter_envs(project.environments, project._id, project.tenantId)
        projects_with_envs_filtered := json.patch(project, [{"op": "replace", "path": "/environments", "value": allowed_envs}])
    ]
}

# projection_project_environments

user_can_access_project_given_project(project) = allowed {
    allowed := user_has_permission_from_bindings("console.company.project.view", project.tenantId)
} {
    not user_has_permission_from_bindings("console.company.project.view", project.tenantId)
    allowed := user_has_permission_from_bindings("console.project.view", project._id)
}

# Used permissions:
#   - console.project.view
#   - console.company.project.view
#   - console.environment.view
#   - console.project.environment.view
projection_project_environments [project] {
    project := input.response.body
    project
    user_can_access_project_given_project(project)
    user_has_permission_from_bindings("console.project.environment.view", project._id)
} {
    project := input.response.body
    project
    user_can_access_project_given_project(project)
    not user_has_permission_from_bindings("console.project.environment.view", project._id)
    user_has_permission_from_bindings("console.company.project.environment.view", project.tenantId)
} {
    originalProject := input.response.body
    user_can_access_project_given_project(originalProject)
    not user_has_permission_from_bindings("console.project.environment.view", originalProject._id)
    not user_has_permission_from_bindings("console.company.project.environment.view", originalProject.tenantId)
    allowed_envs := filter_envs(originalProject.environments, originalProject._id, originalProject.tenantId)
    project := json.patch(originalProject, [{"op": "replace", "path": "environments", "value": allowed_envs}])
}

filter_envs(environments, mongoProjectId, tenantId) = allowed_envs {
    user_has_permission_from_bindings("console.project.environment.view", mongoProjectId)
    allowed_envs := environments
} {
    not user_has_permission_from_bindings("console.project.environment.view", mongoProjectId)
    user_has_permission_from_bindings("console.company.project.environment.view", tenantId)
    allowed_envs := environments
} {
    not user_has_permission_from_bindings("console.project.environment.view", mongoProjectId)
    not user_has_permission_from_bindings("console.company.project.environment.view", tenantId)
    allowed_envs := [y |
        environment := environments[_]
        user_has_permission_from_bindings("console.environment.view", concat(":", [mongoProjectId, environment.envId]))
        y := environment
    ]
}

# filter_values_from_secreted_envs
#
# Used permissions:
#   - console.project.secreted_variables.manage
#
filter_values_from_secreted_envs [env_variables] {
  not user_has_permission_from_bindings("console.project.secreted_variables.manage", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId}] }
  })
  not user_has_permission_from_bindings("console.company.project.secreted_variables.manage", project.tenantId)
  env_variables:= [x |
      envs_from_body:= input.response.body[_]
      x = {"key": envs_from_body.key, "value": ""}
  ]
} {
  user_has_permission_from_bindings("console.project.secreted_variables.manage", input.request.pathParams.projectId)
  env_variables:= input.response.body
}

# allow_deploy
#
# Used permissions:
#   - console.project.deploy.trigger
#
allow_deploy {
  user_has_permission_from_bindings("console.project.deploy.trigger", input.request.pathParams.projectId)
} {
  user_has_permission_from_bindings("console.project.deploy.trigger", input.request.query.projectId[0])
} {
  user_has_permission_from_bindings("console.environment.deploy.trigger", concat(":", [input.request.pathParams.projectId, input.request.body.environment]))
} {
  not user_has_permission_from_bindings("console.project.deploy.trigger", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.deploy.trigger", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.deploy.trigger", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.deploy.trigger", project.tenantId)
}

# allow_pod_delete
#
# Used permissions:
#   - console.project.k8s.pod.delete
#   - console.environment.k8s.pod.delete
#
allow_pod_delete {
  user_has_permission_from_bindings("console.project.k8s.pod.delete", input.request.pathParams.projectId)
} {
  user_has_permission_from_bindings("console.project.k8s.pod.delete", input.request.query.projectId[0])
} {
  user_has_permission_from_bindings("console.environment.k8s.pod.delete", concat(":", [input.request.pathParams.projectId, input.request.pathParams.envId]))
} {
  not user_has_permission_from_bindings("console.project.k8s.pod.delete", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.k8s.pod.delete", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.k8s.pod.delete", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.k8s.pod.delete", project.tenantId)
}

# allow_manage_dashboard
#
# Used permissions:
#   - console.project.dashboard.manage
#   - console.environment.dashboard.manage
#
allow_manage_dashboard {
  user_has_permission_from_bindings("console.project.dashboard.manage", input.request.pathParams.projectId)
} {
  user_has_permission_from_bindings("console.project.dashboard.manage", input.request.query.projectId[0])
} {
  user_has_permission_from_bindings("console.environment.dashboard.manage", concat(":", [input.request.pathParams.projectId, input.request.pathParams.environmentId]))
} {
  not user_has_permission_from_bindings("console.project.dashboard.manage", input.request.pathParams.projectId)
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.pathParams.projectId }] }
  })
  user_has_permission_from_bindings("console.company.project.dashboard.manage", project.tenantId)
} {
  not user_has_permission_from_bindings("console.project.dashboard.manage", input.request.query.projectId[0])
  project := find_one("projects", {
      "$expr": { "$eq": ["$_id", { "$toObjectId": input.request.query.projectId[0]}] }
  })
  user_has_permission_from_bindings("console.company.project.dashboard.manage", project.tenantId)
}

# projection_features_toggle
#
# Used permissions:
#   - console.project.secreted_variables.manage
#
# Projected features toggle are:
#   - ENABLE_PROJECT_CREATION
#   - ENABLE_PERMISSION_MAKE_COMMIT
#   - ENABLE_PERMISSION_MANAGE_SECRET_VARIABLES
#   - ENABLE_PERMISSION_DEPLOY_{ENVID}
#   - ENABLE_PERMISSION_RESTART_POD_{ENVID}
#   - ENABLE_PERMISSION_MANAGE_DASHBOARD_{ENVID}
projection_features_toggle[res] {
  ft_not_allowed := {x |
    some key, val in input.response.body
      ft_checker with input.ft as key
    x = key
  }
  res := object.remove(input.response.body, ft_not_allowed)
}

ft_checker {
  ft := input.ft
  ft == "ENABLE_PROJECT_CREATION"
  not allow_create_project
} {
  ft := input.ft
  ft == "ENABLE_PERMISSION_MAKE_COMMIT"
  not allow_commit
} {
  ft := input.ft
  ft == "ENABLE_PERMISSION_MANAGE_SECRET_VARIABLES"
  not allow_manage_secret_envs
} {
  ft := input.ft
  startswith(ft, "ENABLE_PERMISSION_DEPLOY_")
  env_from_ft := split(ft, "ENABLE_PERMISSION_DEPLOY_")[1]
  not allow_deploy
  not user_has_permission_from_bindings("console.environment.deploy.trigger", concat(":", [input.request.query.projectId[0], env_from_ft]))
} {
  ft := input.ft
  startswith(ft, "ENABLE_PERMISSION_RESTART_POD_")
  env_from_ft := split(ft, "ENABLE_PERMISSION_RESTART_POD_")[1]
  not allow_pod_delete
  not user_has_permission_from_bindings("console.environment.k8s.pod.delete", concat(":", [input.request.query.projectId[0], env_from_ft]))
} {
  ft := input.ft
  startswith(ft, "ENABLE_PERMISSION_MANAGE_DASHBOARD_")
  env_from_ft := split(ft, "ENABLE_PERMISSION_MANAGE_DASHBOARD_")[1]
  not allow_manage_dashboard
  not user_has_permission_from_bindings("console.environment.dashboard.manage", concat(":", [input.request.query.projectId[0], env_from_ft]))
}{
  ft := input.ft
  ft == "ENABLE_PERMISSION_CREATE_SERVICE_REPOSITORY"
  not allow_service_repository_creation
}


# ##################################################################################################
# Utilities

# user_has_permission_from_bindings is an helper function useful to check whether provided
# permission is comprehended in the input user bindings and roles permissions lists.
user_has_permission_from_bindings(permission, resourceId) {
  bindings := input.user.bindings[_]

  filter_bindings_by_permission(bindings, permission)
  bindings.resource.resourceId == resourceId
}

# filter_bindings_by_permission is an helper function useful to filter provided bindings and
# keep those that grant the provided permission (either in the bindings.permissions or in
# each binding.roles role.permissions).
filter_bindings_by_permission(bindings, permission) {
  resourceType := split(permission, ".")[1]
  bindings.resource.resourceType == resourceType
  bindings.permissions[_] == permission
} {
  resourceType := split(permission, ".")[1]
  bindings.resource.resourceType == resourceType

  roles := input.user.roles[_]
  roles.roleId == bindings.roles[_]
  roles.permissions[_] == permission
}

# user_has_group is an helper function useful to check whether provided
# group is listed in the user groups.
user_has_group(group) {
  input.user.groups[_] == group
}
