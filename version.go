package main

import (
	"strconv"
	"strings"
)

type Version string

func (v Version) compareTo(other Version) int {
	currTab := strings.SplitN(string(v), ".", 3)
	otherTab := strings.SplitN(string(other), ".", 3)

	currSuffix := strings.SplitN(currTab[len(currTab)-1], "-", 2)
	otherSuffix := strings.SplitN(otherTab[len(otherTab)-1], "-", 2)
	currTab[len(currTab)-1] = currSuffix[0]
	otherTab[len(otherTab)-1] = otherSuffix[0]

	max := len(currTab)
	if len(otherTab) > max {
		max = len(otherTab)
	}
	for i := 0; i < max; i++ {
		var currInt, otherInt int
		if len(currTab) > i {
			currInt, _ = strconv.Atoi(currTab[i])
		}
		if len(otherTab) > i {
			otherInt, _ = strconv.Atoi(otherTab[i])
		}
		if currInt > otherInt {
			return 1
		}
		if otherInt > currInt {
			return -1
		}
	}

	smax := 0
	if len(currSuffix) == 2 {
		smax = len(currSuffix[1])
	}
	if len(otherSuffix) == 2 && len(otherSuffix[1]) > smax {
		smax = len(otherSuffix[1])
	}
	for i := 0; i < smax; i++ {
		var currByte, otherByte byte
		if len(currSuffix) == 2 && len(currSuffix[1]) > i {
			currByte = currSuffix[1][i]
		}
		if len(otherSuffix) == 2 && len(otherSuffix[1]) > i {
			otherByte = otherSuffix[1][i]
		}
		if currByte > otherByte {
			return 1
		}
		if otherByte > currByte {
			return -1
		}
	}

	return 0
}

// LessThan checks if a version is less than another
func (v Version) LessThan(other Version) bool {
	return v.compareTo(other) == -1
}

// LessThanOrEqualTo checks if a version is less than or equal to another
func (v Version) LessThanOrEqualTo(other Version) bool {
	return v.compareTo(other) <= 0
}

// GreaterThan checks if a version is greater than another
func (v Version) GreaterThan(other Version) bool {
	return v.compareTo(other) == 1
}

// GreaterThanOrEqualTo checks if a version is greater than or equal to another
func (v Version) GreaterThanOrEqualTo(other Version) bool {
	return v.compareTo(other) >= 0
}

// Equal checks if a version is equal to another
func (v Version) Equal(other Version) bool {
	return v.compareTo(other) == 0
}
