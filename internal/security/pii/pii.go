// Package pii provides deterministic masking of personally identifiable
// information for logs, traces and error messages. Per BeyondProd, no raw PII
// (emails, phones, card numbers, full names, addresses) may appear in
// observability pipelines.
//
// The maskers here are pure and allocation-light so they are safe to call on
// hot logging paths.
package pii

import (
	"regexp"
	"strings"
)

var (
	// Luhn-ish 13-19 digit sequences (optionally space/dash separated).
	cardRe = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	// Loose phone matcher: +, digits, spaces, dashes, parens (>=7 digits).
	phoneRe = regexp.MustCompile(`\+?\d[\d ()\-]{6,}\d`)
)

// MaskEmail keeps the first character of the local part and the domain TLD:
// "alice@example.com" -> "a***@***.com".
func MaskEmail(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "***"
	}
	local := email[:at]
	domain := email[at+1:]

	var lead string
	if len(local) > 0 {
		lead = local[:1]
	}
	dot := strings.LastIndexByte(domain, '.')
	tld := ""
	if dot >= 0 {
		tld = domain[dot:] // includes the dot
	}
	return lead + "***@***" + tld
}

// MaskPhone keeps only the last two digits: "+1 415 555 1234" -> "***34".
func MaskPhone(phone string) string {
	digits := make([]rune, 0, len(phone))
	for _, r := range phone {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	if len(digits) < 2 {
		return "***"
	}
	return "***" + string(digits[len(digits)-2:])
}

// MaskName keeps only initials: "Ada Lovelace" -> "A. L.".
func MaskName(name string) string {
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return "***"
	}
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		r := []rune(f)
		if len(r) > 0 {
			parts = append(parts, string(r[0])+".")
		}
	}
	return strings.Join(parts, " ")
}

// MaskPAN masks a primary account number, keeping only the last 4 digits
// (PCI-DSS allows storing/showing the last 4): "4111111111111111" -> "**** 1111".
func MaskPAN(pan string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, pan)
	if len(digits) < 4 {
		return "****"
	}
	return "**** " + digits[len(digits)-4:]
}

// Scrub redacts any card- or phone-like substrings found in free text. Use it
// as a final safety net on log lines and error messages.
func Scrub(s string) string {
	s = cardRe.ReplaceAllStringFunc(s, func(m string) string {
		// Only treat as a card if it has >=13 actual digits.
		if countDigits(m) >= 13 {
			return "[REDACTED_CARD]"
		}
		return m
	})
	s = phoneRe.ReplaceAllStringFunc(s, func(m string) string {
		if countDigits(m) >= 7 {
			return "[REDACTED_PHONE]"
		}
		return m
	})
	return s
}

func countDigits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}
