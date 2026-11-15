import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { reportDisallowedElements, reportMarkdownComponents } from "./reportMarkdownOptions.js";

export default function ReportMarkdown({ children }) {
  return <ReactMarkdown remarkPlugins={[remarkGfm]} components={reportMarkdownComponents} disallowedElements={reportDisallowedElements}>{children}</ReactMarkdown>;
}
