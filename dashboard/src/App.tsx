import { BrowserRouter, Route, Routes } from "react-router-dom";

import { getToken } from "@/api/client";
import { Layout } from "@/components/Layout";
import { TokenPrompt } from "@/components/TokenPrompt";
import { FindingsPage } from "@/pages/FindingsPage";
import { FindingDetailPage } from "@/pages/FindingDetailPage";
import { RulesPage } from "@/pages/RulesPage";
import { RuleDetailPage } from "@/pages/RuleDetailPage";

function App() {
  if (!getToken()) {
    return <TokenPrompt />;
  }
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<FindingsPage />} />
          <Route path="/findings/:pk/:sk" element={<FindingDetailPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/rules/:ruleId" element={<RuleDetailPage />} />
          <Route path="*" element={<FindingsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
