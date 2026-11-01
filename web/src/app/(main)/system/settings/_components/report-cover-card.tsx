"use client";

// report-cover-card.tsx — 报告封面要素配置（机构署名/密级/文档编号前缀），
// 存 settings（report.cover_org / report.cover_classification / report.cover_prefix）。
import * as React from "react";

import { FileTextIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

export function ReportCoverCard() {
  const [values, setValues] = React.useState<Record<string, string>>({
    org: "",
    classification: "内部资料",
    prefix: "FORANG",
  });
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    api
      .settings()
      .then((s) => {
        setValues({
          org: s.report_cover_org ?? "",
          classification: s.report_cover_classification || "内部资料",
          prefix: s.report_cover_prefix || "FORANG",
        });
      })
      .catch(() => undefined);
  }, []);

  const save = () => {
    setSaving(true);
    api
      .setSettings({
        report_cover_org: values.org,
        report_cover_classification: values.classification,
        report_cover_prefix: values.prefix,
      })
      .then(() => toast.success("报告封面配置已保存（下次生成报告生效）"))
      .catch((e) => toast.error(e.message))
      .finally(() => setSaving(false));
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><FileTextIcon className="size-4" /> 报告封面</CardTitle>
        <CardDescription>
          Word / Markdown 报告封面的机构署名、密级与文档编号前缀。交付客户前按需修改，缺省 FORANG 内部资料。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <Label className="text-xs">机构署名（© 行）</Label>
            <Input
              className="mt-1"
              value={values.org}
              onChange={(e) => setValues((v) => ({ ...v, org: e.target.value }))}
              placeholder="FORANG 自主渗透测试平台"
            />
          </div>
          <div>
            <Label className="text-xs">密级</Label>
            <Input
              className="mt-1"
              value={values.classification}
              onChange={(e) => setValues((v) => ({ ...v, classification: e.target.value }))}
              placeholder="内部资料"
            />
          </div>
          <div>
            <Label className="text-xs">文档编号前缀</Label>
            <Input
              className="mt-1"
              value={values.prefix}
              onChange={(e) => setValues((v) => ({ ...v, prefix: e.target.value }))}
              placeholder="FORANG"
            />
          </div>
        </div>
        <Button size="sm" onClick={save} disabled={saving}>
          {saving ? "保存中…" : "保存封面配置"}
        </Button>
      </CardContent>
    </Card>
  );
}
