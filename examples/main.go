package main

import (
	"context"
	"fmt"
	"log"

	"github.com/andywang2011/go-kyc"
)

func main() {
	ctx := context.Background()
	fake := kyc.NewFake(kyc.FakeConfig{})
	start, err := fake.Start(ctx, kyc.StartRequest{
		SubjectID: "user-1",
		ReturnURL: "https://app.example/kyc/callback",
		Locale:    "en",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("redirect:", start.RedirectURL)

	st, err := fake.Status(ctx, start.ExternalID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("status:", st.Status)
}
