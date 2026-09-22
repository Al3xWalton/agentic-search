//! Renders public policy from validated configuration and immutable record selections.
//! Missing approvals remain explicit; untrusted text cannot create Markdown or HTML structure.

#![deny(missing_docs)]

use super::{
    record_types::{
        ApprovalStatus, Assessment, ChildClass, ComplianceManifest, RecordBody, RecordKind,
    },
    records::RecordView,
};
use crate::config::compliance::ValidatedComplianceConfig;

/// Escapes markup and URI delimiters, flattening narrative line controls to inert text.
pub fn escape_markdown(text: &str) -> String {
    let mut escaped = String::new();
    for character in text.chars() {
        match character {
            '\n' | '\t' | '\r' => escaped.push(' '),
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.'
            | '!' | '|' | '~' | ':' | '/' | '?' | '=' | '@' | '%' => {
                escaped.push_str(&format!("&#{};", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn section(title: &str, body: &str) -> String {
    format!("## {title}\n\n{body}\n\n")
}

fn manifest(view: &RecordView) -> Option<&ComplianceManifest> {
    let selected = view.manifest().ok().flatten()?;
    match &selected.body {
        RecordBody::Manifest(manifest) => Some(manifest),
        _ => None,
    }
}

fn assessment(view: &RecordView, kind: RecordKind) -> Option<&Assessment> {
    super::reviews::selected(view)
        .ok()?
        .into_iter()
        .find(|record| record.kind == kind)
        .and_then(|record| record.assessment())
}

fn optional(text: Option<&str>, placeholder: &str) -> String {
    text.map(escape_markdown)
        .unwrap_or_else(|| placeholder.into())
}

fn status(approval: ApprovalStatus) -> &'static str {
    match approval {
        ApprovalStatus::Approved => "Operator-approved assessment",
        ApprovalStatus::Draft => "Draft assessment; approval pending",
    }
}

/// Renders the twelve policy sections without reading any clock, file, token or ticket.
pub fn render(config: &ValidatedComplianceConfig, view: &RecordView) -> String {
    let mut text = String::from("# AVA Search compliance statement\n\n");
    if view
        .manifest()
        .ok()
        .flatten()
        .into_iter()
        .chain(super::reviews::selected(view).unwrap_or_default())
        .any(|record| record.id.starts_with("sample."))
    {
        text.push_str("sample — not an approval\n\n");
    }
    text.push_str(
        &[
            about_section(view),
            reports_section(),
            complaints_section(config),
            unfounded_section(config),
            proactive_section(config),
            illegal_section(config, view),
            children_primary_section(config, view),
            children_priority_section(config, view),
            children_other_section(config, view),
            accountable_section(view),
            retention_section(config),
            changes_section(config),
        ]
        .concat(),
    );
    text.truncate(text.len() - 1);
    text
}

fn about_section(view: &RecordView) -> String {
    let service = manifest(view)
        .map(|manifest| escape_markdown(&manifest.service))
        .unwrap_or_else(|| "AVA Search".into());
    let approval = manifest(view)
        .map(|manifest| status(manifest.approval_status))
        .unwrap_or("Approvals pending; no approved manifest selected");
    section(
        "About this service",
        &format!(
            "{service} is AVA's web-retrieval service. {approval}. This statement \
            describes implemented reporting, record and serving controls. Public \
            operation also requires genuine assessments, approval, delivery \
            arrangements and publication checks. Local operation is not an \
            approval."
        ),
    )
}

fn reports_section() -> String {
    section(
        "Reports and requests",
        concat!(
            "Start at `/v1/reports`. You may report even if you do not use AVA. \
            The eight routes cover illegal content; harmful content for children; \
            intimate images; site complaints; rights removal; data rights; data \
            protection complaints; and online safety complaints.\n\n",
            "These are JSON API forms. Form and email availability is pending \
            deployment. The API records a private reply contact and returns a \
            ticket capability; it sends no email. Keep that capability private. \
            Public status contains progress milestones and a limited outcome, not \
            private evidence. Administrative access requires a separate bearer \
            credential."
        ),
    )
}

fn complaints_section(config: &ValidatedComplianceConfig) -> String {
    let days = super::clock::COMPLAINT_ACK_SECONDS / 86_400;
    let policy = optional(
        config.settings().statement_complaints.as_deref(),
        "[FOUNDER REQUIRED: approved complaints and appeals policy]",
    );
    let contact = optional(
        config.settings().public_contact.as_deref(),
        "[FOUNDER REQUIRED: public contact channel]",
    );
    let ico = optional(
        config.settings().ico_complaints_url.as_deref(),
        "[FOUNDER REQUIRED: ICO complaints information]",
    );
    section(
        "Complaints and appeals",
        &format!(
            "A reviewer considers evidence, records a reasoned decision and may \
            uphold or reverse an appealed outcome. AVA records acknowledgement, \
            progress and decision notices; a recorded delivery attestation is not \
            proof of receipt. Data protection complaints are acknowledged within \
            {days} days, followed by enquiries, progress and an outcome without undue \
            delay.\n\n{policy}\n\nAVA contact: {contact}. You may complain to the \
            ICO and seek judicial remedies where applicable. ICO information: \
            {ico}. Deployment must provide essential communications; delivery is \
            not implemented by this API."
        ),
    )
}

fn unfounded_section(config: &ValidatedComplianceConfig) -> String {
    let version = escape_markdown(&config.settings().unfounded_policy_version);
    let clause = crate::api::v1::reports::MANIFESTLY_UNFOUNDED_CLAUSE;
    section(
        "Manifestly unfounded complaints",
        &format!(
            "Policy version: {version}.\n\n{clause}\n\nThis disposition applies \
            only to site complaints, data protection complaints and online safety \
            complaints. The reviewer records the concluded complaint reference, \
            policy version and reasoned application."
        ),
    )
}

fn proactive_section(config: &ValidatedComplianceConfig) -> String {
    let margin = config.settings().intimate_margin_seconds;
    let seconds = super::clock::INTIMATE_PERIOD_SECONDS;
    let hours = seconds / 3_600;
    let default = super::bounds::BoundKey::IntimateMargin
        .spec()
        .default
        .expect("configured margin has a default");
    let policy = optional(
        config.settings().statement_proactive.as_deref(),
        "[FOUNDER REQUIRED: approved proactive-technology explanation]",
    );
    section(
        "Proactive technology",
        &format!(
            "Serving uses deterministic URL, name and configured hash-list \
            filtering. Reported intimate-image URLs receive protection within {hours} hours: \
            activation is receipt plus {seconds} seconds minus the configured margin \
            of {margin} seconds. The default margin is {default} seconds, making \
            protection immediate. Durable rules retain activation times across \
            restarts, and reasoned reversals are recorded.\n\nThese controls do \
            not classify images or compare visual similarity. They cannot \
            discover every unsafe item; missing evidence, unavailable feeds and \
            downstream crawler or index integration limit coverage. Configured \
            listed data is private and is never disclosed by this \
            statement.\n\n{policy}"
        ),
    )
}

fn measures_text(view: &RecordView) -> String {
    let selected = super::reviews::selected(view).ok().unwrap_or_default();
    let measures = selected.into_iter().find_map(|record| match &record.body {
        RecordBody::Measures(measures) => Some(measures),
        _ => None,
    });
    let Some(measures) = measures else {
        return "[FOUNDER REQUIRED: assessed measures and alternatives]".into();
    };
    let mut text = format!(
        "{} measures:\n\n",
        match measures.approval_status {
            ApprovalStatus::Approved => "Operator-approved",
            ApprovalStatus::Draft => "Draft; approval pending for",
        }
    );
    for row in &measures.rows {
        text.push_str(&format!(
            "- {}: {}. {}. {}\n",
            escape_markdown(row.code.as_str()),
            escape_markdown(&row.description),
            match row.adoption {
                super::measures::Adoption::Required => "required",
                super::measures::Adoption::VoluntaryPendingLegalReview =>
                    "adopted voluntarily; whether it is required for a service of this size \
                    is under legal review",
            },
            measure_disposition(row)
        ));
    }
    text
}

fn measure_disposition(row: &super::measures::MeasureRow) -> String {
    match &row.alternative {
        Some(alternative) => format!(
            "Alternative stated: {}. Duty reasoning: {}. Expression and privacy: {}.",
            escape_markdown(&alternative.measure),
            escape_markdown(&alternative.compliance_reasoning),
            escape_markdown(&alternative.freedom_of_expression_and_privacy)
        ),
        None => "Stated as taken in the selected measures record.".into(),
    }
}

fn controls_text(assessment: &Assessment) -> String {
    let mut text = String::from("Controls and effects stated in this assessment:\n\n");
    for control in &assessment.existing_controls {
        text.push_str(&format!(
            "- {}: {}\n",
            escape_markdown(&control.description),
            escape_markdown(&control.effect)
        ));
    }
    if assessment.approval_status == ApprovalStatus::Draft {
        text.push_str(
            "\n[FOUNDER REQUIRED: approve assessed measures and outstanding \
                decisions for this kind]\n",
        );
    }
    text.push('\n');
    text
}

fn illegal_section(config: &ValidatedComplianceConfig, view: &RecordView) -> String {
    let assessed = assessment(view, RecordKind::Icra);
    let mut body = String::from(
        "Each priority kind requires a separately reasoned assessment. Catalog \
            labels require an authoritative source and version.\n\n",
    );
    for number in 1..=17 {
        let label = optional(
            config.settings().priority_kind_labels[number - 1].as_deref(),
            &format!("[FOUNDER REQUIRED: priority illegal content kind P{number:02}]"),
        );
        body.push_str(&format!("### P{number:02}\n\n{label}\n\n"));
        let risk = assessed.and_then(|assessment| {
            assessment
                .priority_risks
                .iter()
                .find(|risk| risk.kind.as_str() == format!("P{number:02}"))
        });
        if let (Some(assessment), Some(risk)) = (assessed, risk) {
            body.push_str(&format!(
                "{}: {} risk. {}\n\n",
                status(assessment.approval_status),
                risk.level.as_str(),
                escape_markdown(&risk.explanation)
            ));
            body.push_str(&controls_text(assessment));
        } else {
            body.push_str(
                "[FOUNDER REQUIRED: risk assessment, controls and outstanding \
                    decisions for this kind]\n\n",
            );
        }
        body.push_str(
            "A reviewer must assess relevant evidence and the effect of the \
                selected measures for this kind.\n\n",
        );
    }
    body.push_str(&measures_text(view));
    section("Illegal content", &body)
}

fn children_text(view: &RecordView, class: ChildClass, policy: Option<&str>) -> String {
    let access = assessment(view, RecordKind::Caa);
    let access = match access {
        Some(assessment) if assessment.approval_status == ApprovalStatus::Approved => assessment
            .access
            .as_ref()
            .map(|access| {
                format!(
                    "Operator-approved children's access conclusion: {}. {}",
                    escape_markdown(access.conclusion.as_str()),
                    escape_markdown(&access.steps)
                )
            })
            .unwrap_or_else(|| "[FOUNDER REQUIRED: children's access assessment]".into()),
        _ => String::from(
            "Children's access has not been determined by an approved assessment. \
                Draft input is not a determination.",
        ),
    };
    let risk = assessment(view, RecordKind::Cra);
    let risk = risk
        .and_then(|assessment| {
            assessment
                .children
                .as_ref()?
                .classes
                .iter()
                .find(|risk| risk.class == class)
                .map(|risk| {
                    format!(
                        "{}: {} risk. {}",
                        status(assessment.approval_status),
                        risk.level.as_str(),
                        escape_markdown(&risk.explanation)
                    )
                })
        })
        .unwrap_or_else(|| {
            "[FOUNDER REQUIRED: children's risk assessment and measures for this class]".into()
        });
    let policy = optional(
        policy,
        "[FOUNDER REQUIRED: approved child protection policy for this class]",
    );
    format!("{access}\n\n{risk}\n\n{policy}")
}

fn children_primary_section(config: &ValidatedComplianceConfig, view: &RecordView) -> String {
    section(
        "Children: primary priority content",
        &children_text(
            view,
            ChildClass::PrimaryPriority,
            config.settings().statement_children_primary.as_deref(),
        ),
    )
}

fn children_priority_section(config: &ValidatedComplianceConfig, view: &RecordView) -> String {
    section(
        "Children: priority content",
        &children_text(
            view,
            ChildClass::Priority,
            config.settings().statement_children_priority.as_deref(),
        ),
    )
}

fn children_other_section(config: &ValidatedComplianceConfig, view: &RecordView) -> String {
    section(
        "Children: non-designated content",
        &children_text(
            view,
            ChildClass::NonDesignated,
            config.settings().statement_children_other.as_deref(),
        ),
    )
}

fn accountable_section(view: &RecordView) -> String {
    let person = match manifest(view) {
        Some(manifest) => format!(
            "{}: {}. Governance body: {}.",
            status(manifest.approval_status),
            escape_markdown(&manifest.accountable_person),
            escape_markdown(&manifest.governance_body)
        ),
        None => {
            "[FOUNDER REQUIRED: named accountable person]\n\n[FOUNDER REQUIRED: governance body]"
                .into()
        }
    };
    let pending = if manifest(view)
        .is_some_and(|manifest| manifest.approval_status == ApprovalStatus::Approved)
    {
        ""
    } else {
        "\n\n[FOUNDER REQUIRED: named accountable person]"
    };
    section("Accountable person", &format!("{person}{pending}"))
}

fn retention_section(config: &ValidatedComplianceConfig) -> String {
    let months = config.settings().retention_months;
    section(
        "Retention and records",
        &format!(
            "Private ticket payloads are retained for at least {months} calendar \
            months after closure. Eligibility alone does not delete them: an \
            authenticated purge must complete. The ticket audit chain and every \
            immutable assessment, measures, manifest, metrics and review version \
            are retained indefinitely, including superseded versions.\n\nRecord \
            exports contain all envelope versions as escaped HTML with a timed \
            hash receipt. They omit private wrapper salts, commitments, ticket \
            payloads, credentials and listed data. Production response within 48 \
            hours and quarterly mock information-notice drills require \
            operational verification. Record commands use a separate owner and \
            may run while the service owns the ticket journal."
        ),
    )
}

fn changes_section(config: &ValidatedComplianceConfig) -> String {
    let settings = config.settings();
    let mut body = format!(
        "Statement version: {}.\n\nReading-age target: {} years. Reading-age \
            measurement, assistive-technology checks, child presentation and \
            consistency review remain pending. A target is not a tested \
            result.\n\n",
        escape_markdown(&settings.statement_version),
        settings.reading_age,
    );
    for change in &settings.statement_changes {
        body.push_str(&format!(
            "- {} at UTC second {}: {}.\n",
            escape_markdown(&change.version),
            change.at,
            escape_markdown(&change.summary)
        ));
    }
    body.push_str(
        "\nThe running service caches its publication at startup; a restart \
            applies later record changes. Hosting must publish the statement and \
            matching source offer.",
    );
    section("Version and change log", &body)
}
