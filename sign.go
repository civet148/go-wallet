package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/civet148/log"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

const (
	TAG_VALUE_IGNORE = "-"
	TAG_NAME_JSON    = "json"
)

var tagNames = []string{TAG_NAME_JSON}

//MakeSignString make a sign string sort by alpha character
// 				 obj can be url.Values, struct with json tag or map[string]interface{}
func MakeSignString(obj interface{}, excepts ...string) string {
	var strSort string
	if values, ok := obj.(url.Values); ok {
		dic := make(map[string]interface{}, 0)
		for k, v := range values {
			if len(v) > 0 {
				dic[k] = v[0]
			}
		}
		strSort = makeSignStringByMap(dic, excepts...)
	} else {
		typ := reflect.TypeOf(obj)
		val := reflect.ValueOf(obj)
		for typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
			val = val.Elem()
		}
		switch typ.Kind() {
		case reflect.String:
			strSort = obj.(string)
		case reflect.Map:
			strSort = makeSignStringByMap(obj.(map[string]interface{}), excepts...)
		case reflect.Struct:
			strSort = makeSignStringByStruct(typ, val, excepts...)
		default:
			panic(fmt.Sprintf("object type [%s] not support", typ.Name()))
		}
	}
	return strSort
}

func MakeSignSHA256(obj interface{}, excepts ...string) string {
	strToSign := MakeSignString(obj, excepts...)
	digestHash := sha256.Sum256([]byte(strToSign))
	return hex.EncodeToString(digestHash[:])
}

func makeSignStringByStruct(typ reflect.Type, val reflect.Value, excepts ...string) string {
	dic := parseStructFields(typ, val, tagNames...)
	return makeSignStringByMap(dic, excepts...)
}

func makeSignStringByMap(dic map[string]interface{}, excepts ...string) string {
	var keys, values []string
	for _, v := range excepts {
		delete(dic, v)
	}
	for k, _ := range dic {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if strings.Compare(keys[i], keys[j]) < 0 {
			return true
		}
		return false
	})
	for _, key := range keys {
		v := fmt.Sprintf("%s=%v", key, dic[key])
		values = append(values, v)
	}
	return strings.Join(values, "&")
}

// parse struct fields
func parseStructFields(typ reflect.Type, val reflect.Value, tagNames ...string) (dic map[string]interface{}) {

	kind := typ.Kind()
	dic = make(map[string]interface{}, 0)

	if kind == reflect.Struct {
		NumField := val.NumField()
		for i := 0; i < NumField; i++ {
			typField := typ.Field(i)
			valField := val.Field(i)

			if typField.Type.Kind() == reflect.Ptr {
				typField.Type = typField.Type.Elem()
				valField = valField.Elem()
			}
			if !valField.IsValid() || !valField.CanInterface() {
				continue
			}
			saveValueByField(dic, typField, valField, tagNames...) // save field tag value and field value to map
		}
	}
	return dic
}

//trim the field value's first and last blank character and save to map
func saveValueByField(dic map[string]interface{}, field reflect.StructField, val reflect.Value, tagNames ...string) {

	if len(tagNames) == 0 {
		log.Errorf("no tag to save value")
		return
	}

	var tagVal string
	for _, v := range tagNames {
		strTagValue, ignore := getTag(field, v)
		tagVal = handleTagValue(v, strTagValue)
		if ignore {
			break
		}
		if tagVal == "" {
			tagVal = field.Name
		}
		dic[tagVal] = fmt.Sprintf("%v", val.Interface())
	}
}

// get struct field's tag value
func getTag(sf reflect.StructField, tagName string) (strValue string, ignore bool) {

	strValue = sf.Tag.Get(tagName)
	if strValue == TAG_VALUE_IGNORE {
		return "", true
	}
	return
}

func handleTagValue(strTagName, strTagValue string) string {
	if strTagValue == "" {
		return ""
	}
	if strTagName == TAG_NAME_JSON {
		vs := strings.Split(strTagValue, ",")
		strTagValue = vs[0]
	}
	return strTagValue
}
