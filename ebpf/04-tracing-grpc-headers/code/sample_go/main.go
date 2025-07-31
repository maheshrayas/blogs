package main

import (
	"fmt"
	"os"
	"time"
)

type Animals struct {
	Name    string
	Species string
	Age     int
	Weight  float64
	IsWild  bool
}


func main() {

	animal := Animals{
		Name:    "Leo",
		Species: "Lion",
		Age:     5,
		Weight:  190.5,
		IsWild:  true,
	}

	fmt.Printf("PID: %d\n", os.Getpid())
	for {
		_ = hello_int(10)
		_ = hello_int_string(10, "hello")
		_ = hello_struct_pointer(&animal)
		_ = hello_struct_value(animal)
		time.Sleep(10000 * time.Millisecond)
	}
}

func hello_int(x int) int {
	fmt.Printf("hello_int %d\n", x)
	return x
}

func hello_int_string(x int, y string) int {
	fmt.Printf("hello_int_string %d %s\n", x, y)
	return x
}

func hello_struct_pointer(animal *Animals) bool {
	fmt.Printf("Name: %s\n", animal.Name)
	fmt.Printf("Species: %s\n", animal.Species)
	fmt.Printf("Age: %d\n", animal.Age)
	fmt.Printf("Weight: %.2f\n", animal.Weight)
	fmt.Printf("IsWild: %t\n", animal.IsWild)
	return true
}

func hello_struct_value(animal Animals) bool {
	fmt.Printf("Name: %s\n", animal.Name)
	fmt.Printf("Species: %s\n", animal.Species)
	fmt.Printf("Age: %d\n", animal.Age)
	fmt.Printf("Weight: %.2f\n", animal.Weight)
	fmt.Printf("IsWild: %t\n", animal.IsWild)
	return true
}