-- CSAF Analytics Phase 0
-- Atomic promotion from Data Workshop staging tables into canonical tables.
-- Run after 001_schema.sql.

create or replace package pkg_csaf_phase0 as
  function iso_date(p_value in varchar2) return date;
  function csv_number(p_value in varchar2) return number;

  procedure promote_findings (
    p_batch_id      in varchar2,
    p_expected_rows in number default null
  );

  procedure promote_enrichment (
    p_batch_id      in varchar2,
    p_expected_rows in number default null
  );

  procedure purge_stage (p_batch_id in varchar2);
end pkg_csaf_phase0;
/

create or replace package body pkg_csaf_phase0 as

  procedure write_log (
    p_batch_id      in varchar2,
    p_load_type     in varchar2,
    p_source        in varchar2,
    p_source_hash   in varchar2,
    p_status        in varchar2,
    p_rows_affected in number,
    p_message       in varchar2
  ) is
    pragma autonomous_transaction;
  begin
    insert into csaf_load_log (
      batch_id, load_type, source, source_hash, finished_at,
      status, rows_affected, message
    ) values (
      p_batch_id, p_load_type, p_source, p_source_hash, systimestamp,
      p_status, nvl(p_rows_affected, 0), substr(p_message, 1, 2000)
    );
    commit;
  end write_log;

  procedure assert_batch_id(p_batch_id in varchar2) is
  begin
    if p_batch_id is null or not regexp_like(
      p_batch_id,
      '^[0-9]{8}T[0-9]{6}Z_[A-Za-z0-9._-]+$'
    ) then
      raise_application_error(-20100, 'Invalid CSAF batch_id');
    end if;
  end assert_batch_id;

  function iso_date(p_value in varchar2) return date is
  begin
    if trim(p_value) is null then
      return null;
    end if;
    return to_date(substr(trim(p_value), 1, 10), 'YYYY-MM-DD');
  exception
    when others then
      raise_application_error(-20101, 'Invalid ISO date: ' || p_value);
  end iso_date;

  function csv_number(p_value in varchar2) return number is
  begin
    if trim(p_value) is null then
      return null;
    end if;
    return to_number(trim(p_value), 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''');
  exception
    when others then
      raise_application_error(-20102, 'Invalid numeric value: ' || p_value);
  end csv_number;

  procedure promote_findings (
    p_batch_id      in varchar2,
    p_expected_rows in number default null
  ) is
    l_count          number;
    l_identity_count number;
    l_duplicate_count number;
    l_existing_id    number;
    l_existing_hash  varchar2(64);
    l_advisory_id    number;
    l_vendor         varchar2(64);
    l_reference      varchar2(128);
    l_revision       varchar2(64);
    l_source_hash    varchar2(64);
    l_source_file    varchar2(512);
  begin
    assert_batch_id(p_batch_id);

    select count(*)
      into l_count
      from csaf_finding_stage
     where batch_id = p_batch_id;

    if l_count = 0 then
      raise_application_error(-20110, 'No staged findings for batch ' || p_batch_id);
    end if;
    if p_expected_rows is not null and p_expected_rows <> l_count then
      raise_application_error(
        -20111,
        'Finding row count mismatch: expected ' || p_expected_rows ||
        ', staged ' || l_count
      );
    end if;

    select count(*)
      into l_identity_count
      from (
        select vendor, advisory_reference, advisory_revision,
               source_hash, source_filename
          from csaf_finding_stage
         where batch_id = p_batch_id
         group by vendor, advisory_reference, advisory_revision,
                  source_hash, source_filename
      );
    if l_identity_count <> 1 then
      raise_application_error(-20112, 'Batch contains multiple advisory identities');
    end if;

    select max(vendor), max(advisory_reference), max(advisory_revision),
           max(source_hash), max(source_filename)
      into l_vendor, l_reference, l_revision, l_source_hash, l_source_file
      from csaf_finding_stage
     where batch_id = p_batch_id;

    if l_vendor is null or l_reference is null or l_revision is null
       or not regexp_like(l_source_hash, '^[0-9a-f]{64}$', 'i') then
      raise_application_error(-20113, 'Batch advisory metadata is incomplete');
    end if;

    select count(*)
      into l_duplicate_count
      from (
        select cve, product_id
          from csaf_finding_stage
         where batch_id = p_batch_id
         group by cve, product_id
        having count(*) > 1
      );
    if l_duplicate_count > 0 then
      raise_application_error(-20114, 'Duplicate CVE/product rows in staged findings');
    end if;

    begin
      select advisory_id, source_hash
        into l_existing_id, l_existing_hash
        from csaf_advisories
       where vendor = l_vendor
         and advisory_reference = l_reference
         and revision = l_revision;

      if l_existing_hash = l_source_hash then
        write_log(
          p_batch_id, 'advisory', l_source_file, l_source_hash,
          'skipped', 0, 'Same advisory revision and source hash already loaded'
        );
        return;
      end if;

      write_log(
        p_batch_id, 'advisory', l_source_file, l_source_hash,
        'conflict', 0,
        'Same advisory revision exists with a different source hash'
      );
      raise_application_error(
        -20115,
        'CSAF revision conflict for ' || l_reference || ' ' || l_revision
      );
    exception
      when no_data_found then
        null;
    end;

    insert into csaf_advisories (
      vendor, advisory_reference, revision, published_date, revised_date, tlp,
      source_filename, source_url, source_hash
    )
    select max(vendor), max(advisory_reference), max(advisory_revision),
           pkg_csaf_phase0.iso_date(max(published_date)),
           pkg_csaf_phase0.iso_date(max(revised_date)), max(tlp),
           max(source_filename), max(source_url), max(source_hash)
      from csaf_finding_stage
     where batch_id = p_batch_id;

    select advisory_id
      into l_advisory_id
      from csaf_advisories
     where vendor = l_vendor
       and advisory_reference = l_reference
       and revision = l_revision;

    merge into csaf_products p
    using (
      select product_id,
             max(product_family) as family,
             max(product_name) as product_name,
             max(product_version) as product_version,
             max(cpe) as cpe,
             min(pkg_csaf_phase0.iso_date(published_date)) as seen_date
        from csaf_finding_stage
       where batch_id = p_batch_id
       group by product_id
    ) s
       on (p.product_id = s.product_id)
     when matched then update set
       p.family = coalesce(s.family, p.family),
       p.product_name = coalesce(s.product_name, p.product_name),
       p.product_version = coalesce(s.product_version, p.product_version),
       p.cpe = coalesce(s.cpe, p.cpe),
       p.last_seen = case
         when p.last_seen is null then s.seen_date
         when s.seen_date is null then p.last_seen
         else greatest(p.last_seen, s.seen_date)
       end,
       p.updated_at = systimestamp
     when not matched then insert (
       product_id, family, product_name, product_version, cpe,
       first_seen, last_seen
     ) values (
       s.product_id, s.family, s.product_name, s.product_version, s.cpe,
       s.seen_date, s.seen_date
     );

    merge into csaf_vulnerabilities v
    using (
      select cve,
             max(dbms_lob.substr(description, 4000, 1)) as description
        from csaf_finding_stage
       where batch_id = p_batch_id
       group by cve
    ) s
       on (v.cve = s.cve)
     when matched then update set
       v.description = case
         when v.description is null then to_clob(s.description)
         else v.description
       end,
       v.updated_at = systimestamp
     when not matched then insert (
       cve, cve_year, description, first_advisory_id
     ) values (
       s.cve,
       to_number(regexp_substr(s.cve, '^CVE-([0-9]{4})-', 1, 1, null, 1)),
       s.description,
       l_advisory_id
     );

    insert into csaf_facts (
      advisory_id, cve, product_id, status, vex_justification,
      cvss_score, cvss_vector, av, pr, ui, scope_value,
      confidentiality, integrity_value, availability_value,
      pre_auth, scope_changed, high_impact, fix_url, fix_note,
      fix_category, vendor_bug_id
    )
    select l_advisory_id, cve, product_id, status, vex_justification,
           pkg_csaf_phase0.csv_number(cvss_score), cvss_vector, av, pr, ui,
           scope_value,
           confidentiality, integrity, availability,
           pkg_csaf_phase0.csv_number(pre_auth),
           pkg_csaf_phase0.csv_number(scope_changed),
           pkg_csaf_phase0.csv_number(high_impact), fix_url, fix_note,
           fix_category, vendor_bug_id
      from csaf_finding_stage
     where batch_id = p_batch_id;

    commit;
    write_log(
      p_batch_id, 'advisory', l_source_file, l_source_hash,
      'success', l_count, 'Advisory facts promoted successfully'
    );
  exception
    when others then
      rollback;
      if sqlcode not in (-20115) then
        write_log(
          p_batch_id, 'advisory', l_source_file, l_source_hash,
          'failed', 0, sqlerrm
        );
      end if;
      raise;
  end promote_findings;

  procedure promote_enrichment (
    p_batch_id      in varchar2,
    p_expected_rows in number default null
  ) is
    l_count           number;
    l_duplicate_count number;
    l_unknown_count   number;
    l_partial_count   number;
  begin
    assert_batch_id(p_batch_id);

    select count(*)
      into l_count
      from csaf_enrichment_stage
     where batch_id = p_batch_id;

    if l_count = 0 then
      raise_application_error(-20120, 'No staged enrichment for batch ' || p_batch_id);
    end if;
    if p_expected_rows is not null and p_expected_rows <> l_count then
      raise_application_error(
        -20121,
        'Enrichment row count mismatch: expected ' || p_expected_rows ||
        ', staged ' || l_count
      );
    end if;

    select count(*)
      into l_duplicate_count
      from (
        select cve, observed_date
          from csaf_enrichment_stage
         where batch_id = p_batch_id
         group by cve, observed_date
        having count(*) > 1
      );
    if l_duplicate_count > 0 then
      raise_application_error(-20122, 'Duplicate CVE/date rows in enrichment batch');
    end if;

    select count(*)
      into l_unknown_count
      from csaf_enrichment_stage s
     where s.batch_id = p_batch_id
       and not exists (
         select 1 from csaf_vulnerabilities v where v.cve = s.cve
       );
    if l_unknown_count > 0 then
      raise_application_error(
        -20123,
        'Enrichment batch contains CVEs not loaded from findings'
      );
    end if;

    select count(*)
      into l_partial_count
      from csaf_enrichment_stage
     where batch_id = p_batch_id
       and (epss_status <> 'success'
        or kev_status <> 'success'
        or exploit_status <> 'success');

    merge into csaf_enrichment e
    using (
      select cve,
             pkg_csaf_phase0.iso_date(observed_date) as observed_date,
             pkg_csaf_phase0.csv_number(epss) as epss,
             pkg_csaf_phase0.csv_number(epss_percentile) as epss_percentile,
             pkg_csaf_phase0.csv_number(kev) as kev,
             pkg_csaf_phase0.iso_date(kev_added) as kev_added,
             pkg_csaf_phase0.iso_date(kev_due) as kev_due,
             kev_ransomware,
             pkg_csaf_phase0.csv_number(public_exploits) as public_exploits,
             exploit_url,
             epss_status,
             kev_status,
             exploit_status
        from csaf_enrichment_stage
       where batch_id = p_batch_id
    ) s
       on (e.cve = s.cve and e.observed_date = s.observed_date)
     when matched then update set
       e.epss = case when s.epss_status = 'success' then s.epss else e.epss end,
       e.epss_percentile = case
         when s.epss_status = 'success' then s.epss_percentile
         else e.epss_percentile
       end,
       e.kev = case when s.kev_status = 'success' then s.kev else e.kev end,
       e.kev_added = case
         when s.kev_status = 'success' then s.kev_added else e.kev_added
       end,
       e.kev_due = case
         when s.kev_status = 'success' then s.kev_due else e.kev_due
       end,
       e.kev_ransomware = case
         when s.kev_status = 'success' then s.kev_ransomware
         else e.kev_ransomware
       end,
       e.public_exploits = case
         when s.exploit_status = 'success' then s.public_exploits
         else e.public_exploits
       end,
       e.exploit_url = case
         when s.exploit_status = 'success' then s.exploit_url
         else e.exploit_url
       end,
       e.epss_status = s.epss_status,
       e.kev_status = s.kev_status,
       e.exploit_status = s.exploit_status,
       e.imported_at = systimestamp,
       e.last_batch_id = p_batch_id
     when not matched then insert (
       cve, observed_date, epss, epss_percentile, kev, kev_added,
       kev_due, kev_ransomware, public_exploits, exploit_url,
       epss_status, kev_status, exploit_status, last_batch_id
     ) values (
       s.cve, s.observed_date, s.epss, s.epss_percentile, s.kev,
       s.kev_added, s.kev_due, s.kev_ransomware, s.public_exploits,
       s.exploit_url, s.epss_status, s.kev_status, s.exploit_status,
       p_batch_id
     );

    commit;
    write_log(
      p_batch_id, 'enrichment', 'enrichment.csv', null,
      case when l_partial_count > 0 then 'partial' else 'success' end,
      l_count,
      case
        when l_partial_count > 0 then 'Imported with one or more degraded sources'
        else 'Enrichment promoted successfully'
      end
    );
  exception
    when others then
      rollback;
      write_log(
        p_batch_id, 'enrichment', 'enrichment.csv', null,
        'failed', 0, sqlerrm
      );
      raise;
  end promote_enrichment;

  procedure purge_stage(p_batch_id in varchar2) is
  begin
    assert_batch_id(p_batch_id);
    delete from csaf_enrichment_stage where batch_id = p_batch_id;
    delete from csaf_finding_stage where batch_id = p_batch_id;
    commit;
  end purge_stage;

end pkg_csaf_phase0;
/

show errors package pkg_csaf_phase0
show errors package body pkg_csaf_phase0
