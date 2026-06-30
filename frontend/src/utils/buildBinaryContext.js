export const buildBinaryContext = (analysisData) => {
  if (!analysisData) return null;
  return {
    filename:            analysisData.filename           || "unknown",
    architecture:        analysisData.architecture       || "unknown",
    bits:                analysisData.bits               || "unknown",
    ctf_category:        analysisData.ctf_category       || analysisData.category || "unknown",
    confidence:          analysisData.confidence         || "unknown",
    difficulty:          analysisData.difficulty         || "unknown",
    protections: {
      nx:      analysisData.protections?.nx      ?? analysisData.nx      ?? "unknown",
      pie:     analysisData.protections?.pie     ?? analysisData.pie     ?? "unknown",
      canary:  analysisData.protections?.canary  ?? analysisData.canary  ?? "unknown",
      relro:   analysisData.protections?.relro   ?? analysisData.relro   ?? "unknown",
      fortify: analysisData.protections?.fortify ?? analysisData.fortify ?? "unknown",
    },
    predicted_offset:    analysisData.overflow_offset   || analysisData.predicted_offset || null,
    rop_gadgets:        (analysisData.rop_gadgets        || []).slice(0, 8),
    functions:          (analysisData.functions          || []).slice(0, 15),
    pwntools_template:   analysisData.pwntools_template  || analysisData.exploit_template || null,
    flag_formats:        analysisData.flag_formats       || ["flag{"],
    data_flow:           analysisData.data_flow_summary  || analysisData.data_flows || null,
    imports:            (analysisData.imports            || []).slice(0, 15),
    exports:            (analysisData.exports            || []).slice(0, 10),
    libc_version:        analysisData.libc_version       || null,
    format_string_found: analysisData.format_string_detected || analysisData.format_string_found || false,
    cvss_score:          analysisData.cvss_score         || null,
    similar_writeups:   (analysisData.similar_writeups   || []).slice(0, 3),
    disassembly_snippet: analysisData.disassembly_main   || analysisData.disassembly || null,
    hints:               analysisData.hints              || analysisData.ai_hints || null,
  };
};
