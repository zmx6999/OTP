package main

import (
	"181117/OTP"
	"crypto/sha256"
	"fmt"
)

func main()  {
	o:=otp.OTPConfig{"fdgshd",sha256.New}
	fmt.Print(o.GenerateTOTP(60,8))
}