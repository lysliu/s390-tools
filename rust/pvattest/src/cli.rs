// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use clap::{Args, Parser, Subcommand, ValueEnum, ValueHint};
use log::{debug, warn, info};
use utils::CertificateOptions;

/// create, perform, and verify attestation measurements
///
/// Create, perform, and verify attestation measurements for IBM Secure Execution guest systems.
#[derive(Parser, Debug)]
pub struct CliOptions {
    /// Provide more detailed output
    #[arg(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Deprecated short verbose flag (-V) form the C implementation.
    ///
    /// If specified a deprecation warning is emitted,
    #[arg(short = 'V', hide = true, action = clap::ArgAction::Count)]
    verbose_deprecated: u8,

    /// Print version information and exit
    #[arg(long)]
    pub version: bool,

    #[command(subcommand)]
    pub cmd: Command,
}

impl CliOptions {
    pub fn verbosity(&self) -> u8 {
        let verbose_deprecated = self.verbose_deprecated
            + match &self.cmd {
                Command::Create(cmd) => cmd.verbose_deprecated,
                Command::Perform(cmd) => cmd.verbose_deprecated,
                Command::Verify(cmd) => cmd.verbose_deprecated,
                Command::Version => 0,
            };
        if verbose_deprecated > 0 {
            warn!("WARNING: Use of deprecated flag '-V'. Use '-v' or '--verbose' instead.")
        }
        verbose_deprecated
            + self.verbose
            + match &self.cmd {
                Command::Create(cmd) => cmd.verbose,
                Command::Perform(cmd) => cmd.verbose,
                Command::Verify(cmd) => cmd.verbose,
                Command::Version => 0,
            }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create an attestation measurement request
    ///
    /// Create attestation measurement requests to attest an IBM Secure Execution guest. Only build
    /// attestation requests in a trusted environment such as your Workstation. To avoid
    /// compromising the attestation do not publish the attestation request protection key and
    /// shred it after verification. Every 'create' will generate a new, random protection key.
    Create(Box<CreateAttOpt>),

    /// Send the attestation request to the Ultravisor
    ///
    /// Run a measurement of this system through ’/dev/uv’. This device must be accessible and the
    /// attestation Ultravisor facility must be present. The input must be an attestation request
    /// created with ’pvattest create’. Output will contain the original request and the response
    /// from the Ultravisor.
    Perform(PerformAttOpt),

    /// Verify an attestation response
    ///
    /// Verify that a previously generated attestation measurement of an IBM Secure Execution guest
    /// is as expected. Only verify attestation requests in a trusted environment, such as your
    /// workstation. Input must contain the response as produced by ’pvattest perform’. The
    /// protection key must be the one that was used to create the request by ’pvattest create’.
    /// Shred the protection key after the verification. The header must be the IBM Secure
    /// Execution header of the image that was attested during ’pvattest perform’
    Verify(VerifyOpt),

    /// Print version information and exit.
    #[command(aliases(["--version"]), hide(true))]
    Version,
}

#[derive(Args, Debug)]
pub struct CreateAttOpt {
    #[command(flatten)]
    pub certificate_args: CertificateOptions,

    /// Write the generated request to FILE.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub output: String,

    /// Save the protection key as unencrypted GCM-AES256 key in FILE
    ///
    /// Do not publish this key, otherwise your attestation is compromised.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub arpk: String,

    /// Specify-additional data for the request.
    ///
    /// Additional data is provided by the Ultravisor and returned during the attestation request
    /// and is covered by the attestation measurement. Can be specified multiple times.
    /// Optional.
    #[arg(long, value_name = "FLAGS")]
    pub add_data: Vec<AttAddFlags>,

    /// Provide more detailed output.
    #[arg(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Deprecated short verbose flag (-V) form the C implementation.
    ///
    /// If specified a deprecation warning is emitted,
    #[arg(short = 'V', hide = true, action = clap::ArgAction::Count)]
    verbose_deprecated: u8,
}

#[derive(Debug, ValueEnum, Clone, Copy)]
pub enum AttAddFlags {
    /// Request the public host-key-hash of the key that decrypted the SE-image as additional-data
    PhkhImg,
    /// Request the public host-key-hash of the key that decrypted the attestation request as
    /// additional-data
    PhkhAtt,
}

// all members s390x only
#[derive(Args, Debug)]
pub struct PerformAttOpt {
    /// Specify the request to be sent.
    #[cfg(target_arch = "s390x")]
    #[arg(hide=true, short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub input: Option<String>,

    /// Specify the request to be sent.
    #[cfg(target_arch = "s390x")]
    #[arg(value_name = "INPUT", value_hint = ValueHint::FilePath,required_unless_present("input"), conflicts_with("input"))]
    pub input_pos: Option<String>,

    /// Write the result to FILE.
    #[cfg(target_arch = "s390x")]
    #[arg(hide=true, short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub output: Option<String>,

    /// Write the result to FILE.
    #[arg( value_name = "OUTPUT", value_hint = ValueHint::FilePath,required_unless_present("output"), conflicts_with("output"))]
    #[cfg(target_arch = "s390x")]
    pub output_pos: Option<String>,

    /// Provide up to 256 bytes of user input
    ///
    /// User-data is arbitrary user-defined data appended to the Attestation measurement.
    /// It is verified during the Attestation measurement verification.
    /// May be any arbitrary data, as long as it is less or equal to 256 bytes
    #[arg(short, long, value_name = "File", value_hint = ValueHint::FilePath,)]
    pub user_data: Option<String>,

    /// Provide more detailed output.
    #[arg(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Deprecated short verbose flag (-V) form the C implementation.
    ///
    /// If specified a deprecation warning is emitted,
    #[arg(short = 'V', hide = true, action = clap::ArgAction::Count)]
    verbose_deprecated: u8,
}

#[cfg(target_arch = "s390x")]
pub struct PerformAttOptComb<'a> {
    pub input: &'a str,
    pub output: &'a str,
    pub user_data: Option<&'a str>,
}

#[cfg(target_arch = "s390x")]
impl<'a> From<&'a PerformAttOpt> for PerformAttOptComb<'a> {
    fn from(value: &'a PerformAttOpt) -> Self {
        let input = match (&value.input, &value.input_pos) {
            (None, Some(i)) => i,
            (Some(i), None) => i,
            (Some(_), Some(_)) => unreachable!(),
            (None, None) => unreachable!(),
        };
        let output = match (&value.output, &value.output_pos) {
            (None, Some(o)) => o,
            (Some(o), None) => o,
            (Some(_), Some(_)) => unreachable!(),
            (None, None) => unreachable!(),
        };
        let user_data = value.user_data.as_deref();
        log::info!("user_data is {:?}", user_data);

        Self {
            input,
            output,
            user_data,
        }
    }
}

#[derive(Args, Debug)]
pub struct VerifyOpt {
    /// Specify the attestation request to be verified.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub input: String,

    /// Specify the output for the verification result
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub output: Option<String>,

    /// Specifies the header of the guest image.
    ///
    /// Can be an IBM Secure Execution image created by genprotimg or an extracted IBM Secure
    /// Execution header. The header must start at a page boundary.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub hdr: String,

    /// Use FILE as the protection key to decrypt the request
    ///
    /// Do not publish this key, otherwise your attestation is compromised.
    /// Delete this key after verification.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub arpk: String,

    /// Define the output format.
    #[arg(long, value_enum, default_value_t)]
    pub format: VerifyOutputType,

    /// Write the user data to the FILE if any.
    ///
    /// Writes the user data, if the response contains any, to FILE
    /// The user-data is part of the attestation measurement. If the user-data is written to FILE
    /// the user-data was part of the measurement and verified.
    /// Emits a warning if the response contains no user-data
    #[arg(long, short ,value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub user_data: Option<String>,

    /// Provide more detailed output.
    #[arg(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Deprecated short verbose flag (-V) form the C implementation.
    ///
    /// If specified a deprecation warning is emitted,
    #[arg(short = 'V', hide = true, action = clap::ArgAction::Count)]
    verbose_deprecated: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Default)]
pub enum VerifyOutputType {
    /// Use yaml format.
    #[default]
    Yaml,
}
