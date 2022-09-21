package custom_builtins

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	rondTypes "github.com/rond-authz/rond/types"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"gopkg.in/square/go-jose.v2"
)

var ParseJWEDecl = &ast.Builtin{
	Name: "parse_jwe",
	Decl: types.NewFunction(
		types.Args(
			types.A, //input.request.headers: http.Header (map[string][]string)
		),
		types.A, // boolean
	),
}

var ParseJWEFunction = rego.Function1(
	&rego.Function{
		Name: ParseJWEDecl.Name,
		Decl: ParseJWEDecl.Decl,
	},
	func(ctx rego.BuiltinContext, headers *ast.Term) (*ast.Term, error) {

		authorization, err := getHeader(headers, "authorization")
		if err != nil {
			return nil, err
		}

		// authorization header not found
		if authorization == "" {
			return nil, errors.New("authorization is empty string")
		}

		parsed, err := parse_jwe(ctx.Context, authorization)

		t, err := ast.InterfaceToValue(parsed)
		if err != nil {
			return nil, err
		}

		return ast.NewTerm(t), nil
	},
)

type JWEStructure struct {
	Ftype string `json:"ftype"`
	Tower string `json:"token"`
	MemberOf []string `json:"memberOf"`
}

func parse_jwe(ctx context.Context, jwe string) (*JWEStructure, error) {

	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err := jose.ParseEncrypted(jwe)
	if err != nil {
		return nil, err
	}

	var privateKey *rsa.PrivateKey
	privateKey = ctx.Value(rondTypes.PrivateRSAKey{}).(*rsa.PrivateKey)

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate that the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	decrypted, err := object.Decrypt(privateKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf(string(decrypted))

	var jwe_deserialized JWEStructure
	if err =json.Unmarshal(decrypted, &jwe_deserialized); err != nil {
		return nil, err
	}

	return &jwe_deserialized, nil
}

/*
func printContextInternals(ctx interface{}, inner bool) {
    contextValues := reflect.ValueOf(ctx).Elem()
    contextKeys := reflect.TypeOf(ctx).Elem()

    if !inner {
        fmt.Printf("\nFields for %s.%s\n", contextKeys.PkgPath(), contextKeys.Name())
    }

    if contextKeys.Kind() == reflect.Struct {
        for i := 0; i < contextValues.NumField(); i++ {
            reflectValue := contextValues.Field(i)
            reflectValue = reflect.NewAt(reflectValue.Type(), unsafe.Pointer(reflectValue.UnsafeAddr())).Elem()

            reflectField := contextKeys.Field(i)

            if reflectField.Name == "Context" {
                printContextInternals(reflectValue.Interface(), true)
            } else {
                fmt.Printf("field name: %+v\n", reflectField.Name)
                fmt.Printf("value: %+v\n", reflectValue.Interface())
            }
        }
    } else {
        fmt.Printf("context is empty (int)\n")
    }
}
*/