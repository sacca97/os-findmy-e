//! Typed errors, mirroring `app/android/.../domain/Models.kt` (`OpenFinderError`) exactly. The host maps
//! these to user-facing messages; nothing secret ever appears in a message.

use std::fmt;

/// The SRP exchange step at which Grand Slam refused authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrandSlamStep {
    /// Account and machine identity check, before any password-derived proof is sent.
    Init,
    /// Password-derived SRP proof exchange.
    Complete,
}

impl GrandSlamStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            GrandSlamStep::Init => "init",
            GrandSlamStep::Complete => "complete",
        }
    }

    /// Whether this request was sent before the password-derived proof.
    pub const fn before_password(self) -> bool {
        matches!(self, GrandSlamStep::Init)
    }

    const fn label(self) -> &'static str {
        match self {
            GrandSlamStep::Init => "Email verification failed",
            GrandSlamStep::Complete => "Password authentication failed",
        }
    }
}

/// One of the error kinds the app understands. Adding a variant is a change to the shared contract,
/// so they are kept deliberately identical to the Kotlin ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Transport failure (DNS, TCP, TLS), the host is the only detail worth surfacing.
    Network(String),
    /// The credential was refused or is missing.
    Authentication(String),
    /// Grand Slam refused an SRP step; retains the phase and Apple's status fields.
    GrandSlamRefused {
        step: GrandSlamStep,
        ec: Option<i64>,
        em: Option<String>,
    },
    /// Apple answered with its own `ec`/`em`, or an HTTP refusal.
    Rejected { http: Option<u16>, ec: Option<i64>, message: String },
    /// HTTP 429: on Grand Slam, an inconsistent connection or request state (see GSA-LOGIN-TRANSPORT.md), not a rate limit.
    Throttled(String),
    /// A malformed or unexpected answer.
    Backend(String),
    /// Apple keeps answering report requests with an empty body (FindMy.py#185).
    ReportsUnavailable(String),
    /// A piece that is deliberately not ported (never used by the reachable flow).
    NotImplemented(String),
    /// A state blob the caller supplied is not acceptable here.
    State(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Network(h) => write!(f, "could not reach {h}"),
            Error::Authentication(m) => write!(f, "{m}"),
            Error::GrandSlamRefused { step, ec, em } => {
                let ec_text = ec
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "missing".into());
                let em = em.as_deref().filter(|value| !value.is_empty()).unwrap_or("no message");
                write!(f, "{} (ec={ec_text}): {em}", step.label())?;
                if *step == GrandSlamStep::Init {
                    write!(f, ". The password was not sent in this step")?;
                } else if *ec == Some(-22406) {
                    write!(f, ". Apple may also return this for a machine it no longer accepts")?;
                }
                Ok(())
            }
            Error::Rejected { http, ec, message } => {
                let http = http.map(|h| format!("HTTP {h}")).unwrap_or_default();
                let ec = ec.map(|e| format!("ec {e}")).unwrap_or_default();
                let detail = [http, ec].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", ");
                if detail.is_empty() {
                    write!(f, "{message}")
                } else {
                    write!(f, "{message} ({detail})")
                }
            }
            Error::Throttled(m) => write!(f, "{m}"),
            Error::Backend(m) => write!(f, "{m}"),
            Error::ReportsUnavailable(m) => write!(f, "{m}"),
            Error::NotImplemented(m) => write!(f, "not implemented: {m}"),
            Error::State(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Network(e.to_string())
    }
}
