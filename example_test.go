package kyc_test

import (
	"context"
	"fmt"

	"github.com/andywang2011/go-kyc"
)

func ExampleNewFake() {
	ctx := context.Background()
	fake := kyc.NewFake(kyc.FakeConfig{})

	start, err := fake.Start(ctx, kyc.StartRequest{
		SubjectID: "user-42",
		ReturnURL: "https://app.example/kyc/callback",
		Locale:    "en",
	})
	if err != nil {
		panic(err)
	}

	st, err := fake.Status(ctx, start.ExternalID)
	if err != nil {
		panic(err)
	}
	fmt.Println(st.Status)
	// Output: pending
}
