// +build !windows

package link

import (
	"log"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/kayrus/gof5/pkg/config"
)

func Cmd(cfg *config.Config) *exec.Cmd {
	var cmd *exec.Cmd
	if cfg.Driver == "pppd" {
		// VPN
		if cfg.IPv6 && bool(cfg.F5Config.Object.IPv6) {
			cfg.PPPdArgs = append(cfg.PPPdArgs,
				"ipv6cp-accept-local",
				"ipv6cp-accept-remote",
				"+ipv6",
			)
		} else {
			cfg.PPPdArgs = append(cfg.PPPdArgs,
				// TODO: clarify why it doesn't work
				"noipv6", // Unsupported protocol 'IPv6 Control Protocol' (0x8057) received
			)
		}
		if cfg.Debug {
			cfg.PPPdArgs = append(cfg.PPPdArgs,
				"debug",
				"kdebug", "1",
			)
			log.Printf("pppd args: %q", cfg.PPPdArgs)
		}

		switch runtime.GOOS {
		default:
			cmd = exec.Command("pppd", cfg.PPPdArgs...)
		case "freebsd":
			cmd = exec.Command("ppp", "-direct")
		}

		// don't forward parent process signals to a child process
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
			Pgid:    0,
		}
		return cmd
	}
	return nil
}
