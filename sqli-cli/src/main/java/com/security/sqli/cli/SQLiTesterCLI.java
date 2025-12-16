package com.security.sqli.cli;

import com.security.sqli.cli.commands.TestCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.Scanner;

/**
 * Main CLI entry point for SQL Injection Testing Framework.
 *
 * ╔════════════════════════════════════════════════════════════════════╗
 * ║                    LEGAL WARNING - READ CAREFULLY                  ║
 * ║                                                                    ║
 * ║  This tool is designed EXCLUSIVELY for authorized security        ║
 * ║  testing of systems you own or have explicit written permission   ║
 * ║  to test.                                                         ║
 * ║                                                                    ║
 * ║  Unauthorized use of this tool may violate:                       ║
 * ║  • Computer Fraud and Abuse Act (CFAA) - USA                      ║
 * ║  • Computer Misuse Act - UK                                       ║
 * ║  • Similar laws in your jurisdiction                              ║
 * ║                                                                    ║
 * ║  Penalties may include criminal prosecution, fines, and           ║
 * ║  imprisonment.                                                    ║
 * ║                                                                    ║
 * ║  The developers of this tool assume NO LIABILITY for misuse.      ║
 * ╚════════════════════════════════════════════════════════════════════╝
 */
@Command(
    name = "sqli-tester",
    mixinStandardHelpOptions = true,
    version = "SQL Injection Tester 1.0.0",
    description = "Educational SQL injection testing framework for authorized security testing",
    subcommands = {
        TestCommand.class,
        CommandLine.HelpCommand.class
    }
)
public class SQLiTesterCLI implements Runnable {

    @Option(
        names = {"-y", "--yes"},
        description = "Skip authorization confirmation (NOT RECOMMENDED)"
    )
    private boolean skipAuthorization;

    public static void main(String[] args) {
        SQLiTesterCLI cli = new SQLiTesterCLI();

        // If no arguments provided, show help
        if (args.length == 0) {
            args = new String[]{"--help"};
        }

        // Check for authorization before running any command
        if (!cli.skipAuthorization && !cli.confirmAuthorization()) {
            System.err.println("\n[ERROR] Authorization not confirmed. Exiting.");
            System.err.println("You must have explicit permission to test the target system.");
            System.exit(1);
        }

        int exitCode = new CommandLine(cli).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        // Show help by default
        CommandLine.usage(this, System.out);
    }

    /**
     * Confirms that the user has authorization to test the target.
     *
     * @return true if authorized, false otherwise
     */
    private boolean confirmAuthorization() {
        System.out.println("\n" + "═".repeat(70));
        System.out.println("                  AUTHORIZATION CONFIRMATION");
        System.out.println("═".repeat(70));
        System.out.println();
        System.out.println("This tool performs security testing that may be considered");
        System.out.println("HACKING if performed without proper authorization.");
        System.out.println();
        System.out.println("Before proceeding, you MUST confirm that:");
        System.out.println();
        System.out.println("  1. You OWN the target system, OR");
        System.out.println("  2. You have WRITTEN PERMISSION from the system owner");
        System.out.println("  3. You understand the LEGAL RISKS of unauthorized testing");
        System.out.println("  4. You accept FULL RESPONSIBILITY for your actions");
        System.out.println();
        System.out.println("Unauthorized access to computer systems is ILLEGAL in most");
        System.out.println("jurisdictions and may result in criminal prosecution.");
        System.out.println();
        System.out.println("═".repeat(70));
        System.out.println();

        Scanner scanner = new Scanner(System.in);
        System.out.print("Do you have proper authorization to test the target? (yes/no): ");

        String response = scanner.nextLine().trim().toLowerCase();

        if (response.equals("yes") || response.equals("y")) {
            System.out.println();
            System.out.print("Please type 'I AM AUTHORIZED' to confirm: ");
            String confirmation = scanner.nextLine().trim();

            if (confirmation.equals("I AM AUTHORIZED")) {
                System.out.println();
                System.out.println("[✓] Authorization confirmed. Proceeding...");
                System.out.println();
                return true;
            }
        }

        return false;
    }
}
