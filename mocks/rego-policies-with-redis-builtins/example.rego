package policies

import future.keywords.in

foobar = true

# Test Redis GET builtin
allow_with_redis_get {
	key := input.request.pathParams.key
	value := redis_get(key)
	value == "test-value"
}

# Test Redis SET builtin
allow_with_redis_set {
	result := redis_set_with_expiration("test:key", "test-value", 60)
	result == true
}

# Test Redis DEL builtin
allow_with_redis_del {
	key := input.request.pathParams.key
	result := redis_del(key)
	result == true
}
