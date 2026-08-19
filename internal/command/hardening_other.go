//go:build !linux

package command

// preventMemoryInspection is a no-op off Linux, where PR_SET_DUMPABLE has no
// equivalent reached here; the unit's LimitCORE is the portable backstop (M6).
func preventMemoryInspection() error {
	return nil
}
