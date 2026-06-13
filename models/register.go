package models

//import "fmt"
//
//type RecordGeneratorFn func(dc *DomainConfig, ttl uint32, args []any) (Records, error)
//
//var mapBuilderNameToFn = make(map[string]RecordGeneratorFn)
//
//// RegisterGenerator registers a fake type that generates one or more RecordConfigs.
//func RegisterGenerator(typeName string, genFn RecordGeneratorFn) {
//
//	// typenum -> function that runs the generator and returns a list of RecordConfigs.
//	if s, exists := mapBuilderNameToFn[typeName]; exists {
//		panic(fmt.Sprintf("mapGeneratorNameToFn[%s] already in use by %v", typeName, s))
//	}
//	mapBuilderNameToFn[typeName] = genFn
//}
//
//func IsBuilder(name string) bool {
//	_, ok := mapBuilderNameToFn[name]
//	return ok
//}
//
//func (dc *DomainConfig) runBuilder(typeName string, ttl uint32, args []any) (Records, error) {
//	return mapBuilderNameToFn[typeName](dc, ttl, args)
//}
