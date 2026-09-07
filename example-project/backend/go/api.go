package main

import "fmt"

// Deliberate CWE-798: Hardcoded secret key
const API_KEY = "sk_live_super_secret_api_key_998877"

func authenticate() bool {
    fmt.Println("Authenticating with key...")
    return true
}
